use crate::process::ProcessToolExecutor;
use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::artifacts::registry::{ArtifactRegistry, ArtifactType};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;
use std::path::Path;

pub const EVENT_GIT_OPERATION_COMPLETED: &str = "GitOperationCompleted";
pub const EVENT_GIT_OPERATION_FAILED: &str = "GitOperationFailed";

pub struct GitToolRegistry<'a> {
    event_bus: &'a EventBus,
    artifact_registry: &'a mut ArtifactRegistry,
    grant_issuer: &'a GrantIssuer,
    process_executor: ProcessToolExecutor<'a>,
}

impl<'a> GitToolRegistry<'a> {
    pub fn new(
        event_bus: &'a EventBus,
        artifact_registry: &'a mut ArtifactRegistry,
        grant_issuer: &'a GrantIssuer,
    ) -> Self {
        let process_executor = ProcessToolExecutor::new(event_bus, grant_issuer);
        Self {
            event_bus,
            artifact_registry,
            grant_issuer,
            process_executor,
        }
    }

    /// `git status --porcelain` — read-only, requires GitRead.
    pub async fn status(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
    ) -> ToolResult {
        let req = ToolInvocationRequest::GitRead {
            repo_root: repo_root.to_path_buf(),
        };
        if let Some(denied) = self.check_read(ctx, grant, &req) {
            return denied;
        }
        self.run_git_read(ctx, grant, repo_root, &["status", "--porcelain"], "status")
            .await
    }

    /// `git diff [--cached]` — read-only, requires GitRead.
    pub async fn diff(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        cached: bool,
    ) -> ToolResult {
        let req = ToolInvocationRequest::GitRead {
            repo_root: repo_root.to_path_buf(),
        };
        if let Some(denied) = self.check_read(ctx, grant, &req) {
            return denied;
        }
        let args: &[&str] = if cached {
            &["diff", "--cached"]
        } else {
            &["diff"]
        };
        self.run_git_read(ctx, grant, repo_root, args, "diff").await
    }

    /// `git log --oneline -n <limit>` — read-only, requires GitRead.
    pub async fn log(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        limit: u32,
    ) -> ToolResult {
        let req = ToolInvocationRequest::GitRead {
            repo_root: repo_root.to_path_buf(),
        };
        if let Some(denied) = self.check_read(ctx, grant, &req) {
            return denied;
        }
        let n = limit.to_string();
        self.run_git_read(
            ctx,
            grant,
            repo_root,
            &["log", "--oneline", "-n", &n],
            "log",
        )
        .await
    }

    /// `git checkout -b <branch>` — mutating, requires GitWrite.
    pub async fn branch_create(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        branch: &str,
    ) -> ToolResult {
        if let Some(denied) = self.check_write(ctx, grant, repo_root, "branch_create") {
            return denied;
        }
        if !is_safe_ref_name(branch) {
            return self.fail(ctx, format!("Unsafe branch name rejected: {branch:?}"));
        }
        self.run_git_write(
            ctx,
            grant,
            repo_root,
            &["checkout", "-b", branch],
            "branch_create",
        )
        .await
    }

    /// `git checkout <branch>` — mutating, requires GitWrite.
    pub async fn checkout(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        branch: &str,
    ) -> ToolResult {
        if let Some(denied) = self.check_write(ctx, grant, repo_root, "checkout") {
            return denied;
        }
        if !is_safe_ref_name(branch) {
            return self.fail(ctx, format!("Unsafe branch name rejected: {branch:?}"));
        }
        self.run_git_write(ctx, grant, repo_root, &["checkout", branch], "checkout")
            .await
    }

    /// `git add -- <paths>` — mutating, requires GitWrite.
    /// Paths must be relative and must not escape the repo root.
    pub async fn stage(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        relative_paths: &[&str],
    ) -> ToolResult {
        if let Some(denied) = self.check_write(ctx, grant, repo_root, "stage") {
            return denied;
        }
        for p in relative_paths {
            if !is_safe_relative_path(p) {
                return self.fail(ctx, format!("Unsafe stage path rejected: {p:?}"));
            }
        }
        let mut args = vec!["add", "--"];
        args.extend_from_slice(relative_paths);
        self.run_git_write(ctx, grant, repo_root, &args, "stage")
            .await
    }

    /// `git commit -m <message>` — mutating, requires GitWrite.
    /// Captures the commit hash and registers a Diff artifact.
    pub async fn commit(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        message: &str,
    ) -> ToolResult {
        if let Some(denied) = self.check_write(ctx, grant, repo_root, "commit") {
            return denied;
        }
        if message.is_empty() {
            return self.fail(ctx, "Commit message must not be empty".to_string());
        }

        // Run the commit
        let commit_result = self
            .run_git_write(ctx, grant, repo_root, &["commit", "-m", message], "commit")
            .await;

        if commit_result.status != ToolStatus::Succeeded {
            return commit_result;
        }

        // Capture the commit hash for artifact registration
        let hash_result = self
            .run_git_read(ctx, grant, repo_root, &["rev-parse", "HEAD"], "rev-parse")
            .await;

        let commit_hash = match &hash_result.output {
            ToolOutput::Text(t) => t.trim().to_string(),
            _ => {
                return self.fail(ctx, "Failed to read commit hash after commit".to_string());
            }
        };

        // Register a Diff artifact keyed on the commit hash
        let artifact = match self.artifact_registry.register_text_artifact(
            &commit_hash,
            ctx.task_id.to_string().as_str(),
            ArtifactType::Diff,
            None,
            json!({
                "repo_root": repo_root,
                "commit_hash": commit_hash,
                "commit_message": message,
                "invocation_id": ctx.invocation_id,
            }),
        ) {
            Ok(a) => a,
            Err(e) => {
                return self.fail(
                    ctx,
                    format!("Commit succeeded but artifact registration failed: {e}"),
                );
            }
        };

        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_GIT_OPERATION_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "commit",
                "commit_hash": commit_hash,
                "artifact_id": artifact.artifact_id,
            }),
        );

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Text(commit_hash),
            artifact: Some(artifact),
            error_message: None,
        }
    }

    // ── internal helpers ────────────────────────────────────────────────────

    fn check_read(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        req: &ToolInvocationRequest,
    ) -> Option<ToolResult> {
        let engine = PolicyEngine::new(Some(self.event_bus));
        match engine.evaluate_checked(grant, req) {
            Ok(PolicyDecision::Allow { .. }) => None,
            Ok(PolicyDecision::Deny { reason }) => {
                Some(self.fail(ctx, format!("Policy Engine denied git read: {reason}")))
            }
            Err(e) => Some(self.fail(ctx, format!("Failed to persist git read audit: {e}"))),
        }
    }

    fn check_write(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        operation: &str,
    ) -> Option<ToolResult> {
        let req = ToolInvocationRequest::GitWrite {
            repo_root: repo_root.to_path_buf(),
            operation: operation.to_string(),
        };
        let engine = PolicyEngine::new(Some(self.event_bus));
        match engine.evaluate_checked(grant, &req) {
            Ok(PolicyDecision::Allow { .. }) => None,
            Ok(PolicyDecision::Deny { reason }) => Some(self.fail(
                ctx,
                format!("Policy Engine denied git write ({operation}): {reason}"),
            )),
            Err(e) => Some(self.fail(ctx, format!("Failed to persist git write audit: {e}"))),
        }
    }

    async fn run_git_read(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        git_args: &[&str],
        operation: &str,
    ) -> ToolResult {
        self.run_git(ctx, grant, repo_root, git_args, operation)
            .await
    }

    async fn run_git_write(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        repo_root: &Path,
        git_args: &[&str],
        operation: &str,
    ) -> ToolResult {
        self.run_git(ctx, grant, repo_root, git_args, operation)
            .await
    }

    async fn run_git(
        &self,
        ctx: &ToolContext,
        _grant: &CapabilityGrant,
        repo_root: &Path,
        git_args: &[&str],
        operation: &str,
    ) -> ToolResult {
        use chrono::Duration;
        use kernel::permissions::types::Capability;

        // Issue a short-lived ProcessExec grant scoped to `git` in this repo.
        let process_grant = self.grant_issuer.issue_grant(
            &ctx.agent_id,
            ctx.task_id,
            vec![Capability::ProcessExec {
                program: "git".to_string(),
                allowed_args_prefix: git_args.iter().map(|s| s.to_string()).collect(),
                allowed_workdir: repo_root.to_path_buf(),
            }],
            Some(Duration::minutes(5)),
        );

        let args: Vec<String> = git_args.iter().map(|s| s.to_string()).collect();
        let result = self
            .process_executor
            .execute_process(ctx, &process_grant, "git", &args, repo_root, Some(30))
            .await;

        if result.status == ToolStatus::Succeeded {
            let output_text = match &result.output {
                ToolOutput::ProcessResult { stdout, .. } => stdout.clone(),
                _ => String::new(),
            };
            let _ = self.event_bus.emit_event(
                Some(&ctx.task_id.to_string()),
                EVENT_GIT_OPERATION_COMPLETED,
                json!({
                    "invocation_id": ctx.invocation_id,
                    "operation": operation,
                    "output_preview": &output_text[..output_text.len().min(256)],
                }),
            );
            ToolResult {
                invocation_id: ctx.invocation_id,
                status: ToolStatus::Succeeded,
                output: ToolOutput::Text(output_text),
                artifact: None,
                error_message: None,
            }
        } else {
            let msg = result
                .error_message
                .unwrap_or_else(|| format!("git {operation} failed"));
            let _ = self.event_bus.emit_event(
                Some(&ctx.task_id.to_string()),
                EVENT_GIT_OPERATION_FAILED,
                json!({
                    "invocation_id": ctx.invocation_id,
                    "operation": operation,
                    "error": msg,
                }),
            );
            ToolResult {
                invocation_id: ctx.invocation_id,
                status: result.status,
                output: ToolOutput::Empty,
                artifact: None,
                error_message: Some(msg),
            }
        }
    }

    fn fail(&self, ctx: &ToolContext, message: String) -> ToolResult {
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_GIT_OPERATION_FAILED,
            json!({ "invocation_id": ctx.invocation_id, "error": message }),
        );
        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Failed,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(message),
        }
    }
}

/// Rejects ref names that contain shell-special characters or path separators.
fn is_safe_ref_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '/'))
        && !name.starts_with('-')
        && !name.contains("..")
        && !name.ends_with('/')
}

/// Rejects paths that are absolute, contain `..`, or contain shell-special characters.
fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return false;
    }
    !path.contains("..")
        && path
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '/' | '\\' | '.' | ' '))
}
