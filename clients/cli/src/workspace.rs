//! Governed workspace provisioning (Phase 3A integration gate).
//!
//! Wraps `skyos_provisioner::RepositoryProvisioner` so every provisioning run
//! goes through the kernel's governed execution path:
//!
//! 1. **Authorization** — the request is evaluated by `PolicyEngine` against a
//!    `CapabilityGrant`. Provisioning performs two kinds of mutation inside the
//!    repository: Git metadata (worktree add/remove) and filesystem writes
//!    under `.sky/`. Both existing capability types are required:
//!    `GitWrite { repo_root }` and `FileSystemWrite { root }`. A missing or
//!    insufficient grant fails closed with `ProvisionError::PermissionDenied`
//!    *before* the provisioner touches the disk. No new grant variants are
//!    introduced.
//! 2. **Audit** — `WorkspaceProvisioningStarted`, `WorkspaceProvisioned`,
//!    `WorkspaceProvisioningFailed`, and `WorkspaceProvisioningRecovered`
//!    events are written to the durable event ledger, correlated by task ID.
//!    `PolicyEngine` separately records `PermissionGranted` /
//!    `PermissionDenied` for the authorization step itself.
//! 3. **Execution** — only after both checks succeed does the underlying
//!    provisioner run.

use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use kernel::tasks::store::TaskStore;
use skyos_provisioner::errors::ProvisionError;
use skyos_provisioner::models::{DirtyTreePolicy, GitStatusReport, WorkspaceContext};
use skyos_provisioner::provisioner::{GitAdapter, RepositoryProvisioner};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

pub const EVENT_WORKSPACE_PROVISIONING_STARTED: &str = "WorkspaceProvisioningStarted";
pub const EVENT_WORKSPACE_PROVISIONED: &str = "WorkspaceProvisioned";
pub const EVENT_WORKSPACE_PROVISIONING_FAILED: &str = "WorkspaceProvisioningFailed";
pub const EVENT_WORKSPACE_PROVISIONING_RECOVERED: &str = "WorkspaceProvisioningRecovered";

/// Request parameters for one governed provisioning run.
pub struct ProvisionRequest<'a> {
    pub task_id: uuid::Uuid,
    pub project_id: &'a str,
    pub target_branch: &'a str,
    pub base_commit: Option<&'a str>,
    pub dirty_policy: DirtyTreePolicy,
}

pub struct GovernedProvisioner<'a> {
    task_store: &'a TaskStore,
    event_bus: &'a EventBus,
    policy_engine: PolicyEngine<'a>,
    git_adapter: Arc<dyn GitAdapter>,
}

impl<'a> GovernedProvisioner<'a> {
    pub fn new(
        task_store: &'a TaskStore,
        event_bus: &'a EventBus,
        git_adapter: Arc<dyn GitAdapter>,
    ) -> Self {
        Self {
            task_store,
            event_bus,
            policy_engine: PolicyEngine::new(Some(event_bus)),
            git_adapter,
        }
    }

    /// Provision an isolated workspace after kernel authorization.
    ///
    /// Failure ordering (fail closed, always auditable):
    /// - Denied grant → `PermissionDenied` (ledger holds `PermissionDenied`
    ///   + `WorkspaceProvisioningFailed`; no disk mutation).
    /// - Policy engine audit failure → `GitError`-free generic error path;
    ///   the request is aborted before execution.
    /// - Execution failure → the original `ProvisionError`, with a
    ///   `WorkspaceProvisioningFailed` event carrying the error string.
    pub async fn provision(
        &self,
        sandbox_root: &Path,
        request: &ProvisionRequest<'_>,
        grant: &CapabilityGrant,
    ) -> Result<WorkspaceContext, ProvisionError> {
        let task_str = request.task_id.to_string();

        // ── WP1a: the task must exist in the durable ledger ──────────────────
        let task = self.task_store.get_task(&request.task_id).map_err(|e| {
            ProvisionError::GitError(format!("task ledger lookup failed: {e}"))
        })?;
        if task.is_none() {
            let reason = format!("Task {task_str} is not registered in the runtime ledger");
            self.emit(
                Some(&task_str),
                EVENT_WORKSPACE_PROVISIONING_FAILED,
                serde_json::json!({
                    "task_id": task_str,
                    "project_id": request.project_id,
                    "stage": "validation",
                    "error": reason,
                }),
            )?;
            return Err(ProvisionError::TaskNotFound(task_str));
        }

        // ── WP1: kernel authorization before any mutation ───────────────────
        // The worktree lives at <project>/.sky/worktrees/<task>, so both
        // capabilities are scoped to the project directory. Resolve the
        // relative project_id against the sandbox so lexical policy matching
        // compares absolute paths.
        let project_path = sandbox_root.join(request.project_id);
        let requests = [
            ToolInvocationRequest::GitWrite {
                repo_root: project_path.clone(),
                operation: "worktree.provision".to_string(),
            },
            ToolInvocationRequest::FileSystemWrite {
                requested_path: project_path.join(".sky"),
            },
        ];

        for tool_request in &requests {
            let decision = self
                .policy_engine
                .evaluate_checked(grant, tool_request)
                .map_err(|e| {
                    ProvisionError::GitError(format!("policy audit could not be persisted: {e}"))
                })?;
            if let PolicyDecision::Deny { reason } = decision {
                self.emit(
                    Some(&task_str),
                    EVENT_WORKSPACE_PROVISIONING_FAILED,
                    serde_json::json!({
                        "task_id": task_str,
                        "project_id": request.project_id,
                        "stage": "authorization",
                        "error": reason,
                    }),
                )?;
                return Err(ProvisionError::PermissionDenied(reason));
            }
        }

        // ── WP2: durable lifecycle events ───────────────────────────────────
        self.emit(
            Some(&task_str),
            EVENT_WORKSPACE_PROVISIONING_STARTED,
            serde_json::json!({
                "task_id": task_str,
                "project_id": request.project_id,
                "branch": request.target_branch,
                "base_commit": request.base_commit,
                "grant_id": grant.grant_id,
            }),
        )?;

        let provisioner = RepositoryProvisioner::new(
            sandbox_root,
            Arc::clone(&self.git_adapter),
            request.dirty_policy.clone(),
        )?;

        match provisioner
            .provision_workspace(
                &task_str,
                request.project_id,
                request.target_branch,
                request.base_commit,
            )
            .await
        {
            Ok(context) => {
                if let Err(ledger_err) = self.emit(
                    Some(&task_str),
                    EVENT_WORKSPACE_PROVISIONED,
                    serde_json::json!({
                        "task_id": task_str,
                        "project_id": request.project_id,
                        "branch": request.target_branch,
                        "canonical_root": context.canonical_root.display().to_string(),
                        "workspace_kind": context.workspace_kind,
                        "created_at": context.created_at,
                    }),
                ) {
                    // A success that cannot be durably audited must not stand:
                    // roll the completed workspace back so no partially
                    // published (unaudited) workspace survives a ledger write
                    // failure, and the next attempt starts clean.
                    let repo_path = sandbox_root.join(request.project_id);
                    let _ = self
                        .git_adapter
                        .remove_worktree(&repo_path, &context.canonical_root);
                    let context_file = repo_path
                        .join(".sky")
                        .join("workspaces")
                        .join(format!("{}.json", task_str));
                    let _ = std::fs::remove_file(context_file);
                    return Err(ledger_err);
                }
                Ok(context)
            }
            Err(err) => {
                self.emit(
                    Some(&task_str),
                    EVENT_WORKSPACE_PROVISIONING_FAILED,
                    serde_json::json!({
                        "task_id": task_str,
                        "project_id": request.project_id,
                        "stage": "execution",
                        "error": err.to_string(),
                    }),
                )?;
                Err(err)
            }
        }
    }

    /// Run interrupted-provisioning recovery for a project and audit the count.
    ///
    /// The event is emitted unconditionally (including count = 0) so audits can
    /// distinguish "recovery ran and found nothing" from "recovery never ran".
    pub async fn recover(
        &self,
        sandbox_root: &Path,
        project_id: &str,
    ) -> Result<usize, ProvisionError> {
        let provisioner = RepositoryProvisioner::new(
            sandbox_root,
            Arc::clone(&self.git_adapter),
            DirtyTreePolicy::IsolateMainTreeUntouched,
        )?;

        match provisioner
            .recover_interrupted_provisioning(project_id)
            .await
        {
            Ok(count) => {
                self.emit(
                    None,
                    EVENT_WORKSPACE_PROVISIONING_RECOVERED,
                    serde_json::json!({
                        "project_id": project_id,
                        "recovered_count": count,
                    }),
                )?;
                Ok(count)
            }
            Err(err) => Err(err),
        }
    }

    /// Ledger writes are mandatory: an unauditable operation is a failure.
    fn emit(
        &self,
        task_id: Option<&str>,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), ProvisionError> {
        self.event_bus
            .emit_event(task_id, event_type, payload)
            .map_err(|e| {
                ProvisionError::GitError(format!(
                    "durable ledger write failed for {event_type}: {e}"
                ))
            })?;
        Ok(())
    }
}

// ── Real Git adapter ───────────────────────────────────────────────────────────

/// Typed Git operations invoked as fixed `git` argv vectors (never a shell
/// string), suitable for the provisioner's `GitAdapter` contract.
pub struct GitCliAdapter;

impl GitCliAdapter {
    fn git(repo: &Path, args: &[&str]) -> Result<String, ProvisionError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .map_err(|e| ProvisionError::GitError(format!("failed to spawn git: {e}")))?;
        if !output.status.success() {
            return Err(ProvisionError::GitError(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl GitAdapter for GitCliAdapter {
    fn inspect_status(&self, repo_path: &Path) -> Result<GitStatusReport, ProvisionError> {
        let porcelain = Self::git(repo_path, &["status", "--porcelain"])?;
        let branch = Self::git(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"])?
            .trim()
            .to_string();
        let head = Self::git(repo_path, &["rev-parse", "HEAD"])
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let mut staged = Vec::new();
        let mut unstaged = Vec::new();
        let mut untracked = Vec::new();
        for line in porcelain.lines() {
            if line.len() < 3 {
                continue;
            }
            let path = PathBuf::from(line[3..].trim_end());
            let (x, y) = (line.as_bytes()[0], line.as_bytes()[1]);
            match (x, y) {
                (b'?', b'?') => untracked.push(path),
                _ => {
                    if x != b' ' {
                        staged.push(path.clone());
                    }
                    if y != b' ' {
                        unstaged.push(path);
                    }
                }
            }
        }
        let is_clean = staged.is_empty() && unstaged.is_empty() && untracked.is_empty();
        Ok(GitStatusReport {
            active_branch: branch,
            head_commit: head,
            staged_files: staged,
            unstaged_files: unstaged,
            untracked_files: untracked,
            is_clean,
        })
    }

    fn create_worktree(
        &self,
        repo_path: &Path,
        worktree_path: &Path,
        branch: &str,
        base_commit: Option<&str>,
    ) -> Result<(), ProvisionError> {
        let path_str = worktree_path
            .to_str()
            .ok_or_else(|| ProvisionError::GitError("worktree path is not UTF-8".into()))?;
        match base_commit {
            Some(base) => {
                Self::git(repo_path, &["worktree", "add", "-b", branch, path_str, base])?;
            }
            None => {
                Self::git(repo_path, &["worktree", "add", "-b", branch, path_str])?;
            }
        }
        Ok(())
    }

    fn remove_worktree(&self, repo_path: &Path, worktree_path: &Path) -> Result<(), ProvisionError> {
        if !worktree_path.exists() {
            return Ok(());
        }
        let path_str = worktree_path.to_string_lossy();
        // Best-effort: `git worktree remove` can refuse (e.g. untracked files
        // in a staged tmp dir); fall back to deleting the directory and
        // pruning the administrative files.
        let _ = Self::git(repo_path, &["worktree", "remove", "--force", &path_str]);
        let _ = std::fs::remove_dir_all(worktree_path);
        let _ = Self::git(repo_path, &["worktree", "prune"]);
        Ok(())
    }

    fn repair_worktree(&self, repo_path: &Path, worktree_path: &Path) -> Result<(), ProvisionError> {
        let path_str = worktree_path.to_string_lossy();
        Self::git(repo_path, &["worktree", "repair", &path_str])?;
        Ok(())
    }
}
