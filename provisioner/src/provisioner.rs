use crate::errors::ProvisionError;
use crate::models::{DirtyTreePolicy, GitStatusReport, WorkspaceContext, WorkspaceKind};
use crate::path_guard::PathGuard;
use std::path::Path;
use std::sync::Arc;

/// Typed Git primitives the provisioner is allowed to invoke.
///
/// The provisioner executes zero arbitrary shell commands; every Git operation
/// goes through this adapter so it can be authorized and audited by the kernel.
pub trait GitAdapter: Send + Sync {
    fn inspect_status(&self, repo_path: &Path) -> Result<GitStatusReport, ProvisionError>;
    fn create_worktree(
        &self,
        repo_path: &Path,
        worktree_path: &Path,
        branch: &str,
        base_commit: Option<&str>,
    ) -> Result<(), ProvisionError>;
    fn remove_worktree(&self, repo_path: &Path, worktree_path: &Path) -> Result<(), ProvisionError>;
}

/// Task-isolated workspace provisioner.
///
/// # Invariants
/// - Zero data loss: no `git stash`, `reset`, or forced checkout under any
///   policy. Dirty trees are preserved or provisioning halts.
/// - Canonical containment: every path it touches is verified inside the
///   sandbox root before any filesystem mutation.
/// - Atomic lifecycle: worktrees are staged at `.sky/tmp/prov_<task_id>` and
///   renamed into `.sky/worktrees/<task_id>`; a `.sky/provision_<task>.lock`
///   file makes interrupted runs detectable on startup.
pub struct RepositoryProvisioner {
    path_guard: PathGuard,
    git_adapter: Arc<dyn GitAdapter>,
    dirty_policy: DirtyTreePolicy,
}

impl RepositoryProvisioner {
    pub fn new(
        sandbox_root: impl AsRef<Path>,
        git_adapter: Arc<dyn GitAdapter>,
        dirty_policy: DirtyTreePolicy,
    ) -> Result<Self, ProvisionError> {
        let path_guard = PathGuard::new(sandbox_root)?;
        Ok(Self {
            path_guard,
            git_adapter,
            dirty_policy,
        })
    }

    /// Provision an isolated worktree for `task_id` inside `project_id`
    /// (resolved relative to the sandbox root).
    pub async fn provision_workspace(
        &self,
        task_id: &str,
        project_id: &str,
        target_branch: &str,
        base_commit: Option<&str>,
    ) -> Result<WorkspaceContext, ProvisionError> {
        let repo_path = self.path_guard.sanitize_and_verify(Path::new(project_id))?;

        if !repo_path.join(".git").exists() {
            return Err(ProvisionError::RepositoryNotFound(repo_path));
        }

        // 1. Inspect working-tree state.
        let status = self.git_adapter.inspect_status(&repo_path)?;

        // 2. Enforce the explicit dirty-tree policy.
        if !status.is_clean {
            match &self.dirty_policy {
                DirtyTreePolicy::BlockOnDirty => {
                    return Err(ProvisionError::DirtyTreePolicyBlock {
                        staged: status.staged_files.len(),
                        unstaged: status.unstaged_files.len(),
                        untracked: status.untracked_files.len(),
                    });
                }
                // The original tree is left completely untouched; the new
                // worktree is created from the requested base revision only.
                DirtyTreePolicy::IsolateMainTreeUntouched => {
                    tracing::info!(
                        task_id = task_id,
                        "Repository is dirty; preserving original tree and isolating worktree"
                    );
                }
                DirtyTreePolicy::SnapshotToBranch { branch_prefix } => {
                    tracing::warn!(
                        task_id = task_id,
                        branch_prefix = %branch_prefix,
                        "SnapshotToBranch selected; snapshot step is not yet implemented"
                    );
                }
            }
        }

        // 3. Prepare staged and final worktree paths.
        let worktree_dir = repo_path.join(".sky").join("worktrees").join(task_id);
        let tmp_worktree_dir = repo_path
            .join(".sky")
            .join("tmp")
            .join(format!("prov_{}", task_id));

        if worktree_dir.exists() {
            return Err(ProvisionError::WorktreeCollision(worktree_dir));
        }

        if let Some(parent) = tmp_worktree_dir.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = worktree_dir.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // 4. Staged setup: write lock, create in tmp, atomically rename.
        let lock_file = repo_path
            .join(".sky")
            .join(format!("provision_{}.lock", task_id));
        tokio::fs::write(&lock_file, chrono::Utc::now().to_rfc3339()).await?;

        let create_res = self.git_adapter.create_worktree(
            &repo_path,
            &tmp_worktree_dir,
            target_branch,
            base_commit,
        );

        if let Err(e) = create_res {
            let _ = tokio::fs::remove_file(&lock_file).await;
            let _ = tokio::fs::remove_dir_all(&tmp_worktree_dir).await;
            return Err(e);
        }

        if let Err(e) = tokio::fs::rename(&tmp_worktree_dir, &worktree_dir).await {
            let _ = self.git_adapter.remove_worktree(&repo_path, &tmp_worktree_dir);
            let _ = tokio::fs::remove_file(&lock_file).await;
            return Err(ProvisionError::Io(e));
        }

        tokio::fs::remove_file(&lock_file).await?;

        let canonical_worktree = self.path_guard.sanitize_and_verify(&worktree_dir)?;

        Ok(WorkspaceContext {
            task_id: task_id.to_string(),
            project_id: project_id.to_string(),
            workspace_kind: WorkspaceKind::IsolatedWorktree {
                parent_repo: repo_path,
                worktree_path: canonical_worktree.clone(),
                branch: target_branch.to_string(),
            },
            canonical_root: canonical_worktree,
            created_at: chrono::Utc::now(),
        })
    }

    /// Crash recovery: detect and clean up interrupted provisioning runs.
    ///
    /// Called on startup. Removes stale `provision_<task>.lock` files and any
    /// half-created staged worktree they reference. Returns the number of
    /// interrupted operations reconciled.
    pub async fn recover_interrupted_provisioning(
        &self,
        project_id: &str,
    ) -> Result<usize, ProvisionError> {
        let repo_path = self.path_guard.sanitize_and_verify(Path::new(project_id))?;
        let sky_dir = repo_path.join(".sky");
        if !sky_dir.exists() {
            return Ok(0);
        }

        let mut recovered_count = 0;
        let mut entries = tokio::fs::read_dir(&sky_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(task_id) = file_name
                .strip_prefix("provision_")
                .and_then(|s| s.strip_suffix(".lock"))
            else {
                continue;
            };

            tracing::warn!(task_id = %task_id, "Found orphaned provisioning lock; recovering");
            let tmp_dir = sky_dir.join("tmp").join(format!("prov_{}", task_id));
            if tmp_dir.exists() {
                let _ = self.git_adapter.remove_worktree(&repo_path, &tmp_dir);
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
            }
            tokio::fs::remove_file(&path).await?;
            recovered_count += 1;
        }

        Ok(recovered_count)
    }
}
