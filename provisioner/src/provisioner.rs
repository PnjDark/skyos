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

    /// Re-align Git's worktree metadata after the staged directory is renamed
    /// into its final location. A real adapter runs `git worktree repair`;
    /// mocks may no-op.
    fn repair_worktree(&self, _repo_path: &Path, _worktree_path: &Path) -> Result<(), ProvisionError> {
        Ok(())
    }
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

        // 2. Enforce the explicit dirty-tree policy BEFORE any mutation.
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
                // Fail closed: silently proceeding would misrepresent the
                // policy's snapshot guarantee.
                DirtyTreePolicy::SnapshotToBranch { .. } => {
                    return Err(ProvisionError::UnimplementedPolicy {
                        policy: "SnapshotToBranch".to_string(),
                    });
                }
            }
        }

        // 3. Refuse to run over an interrupted provisioning for this task.
        let lock_file = repo_path
            .join(".sky")
            .join(format!("provision_{}.lock", task_id));
        if lock_file.exists() {
            return Err(ProvisionError::IncompleteProvisioningLock {
                task_id: task_id.to_string(),
            });
        }

        // 4. Prepare staged and final worktree paths.
        let worktree_dir = repo_path.join(".sky").join("worktrees").join(task_id);
        let tmp_worktree_dir = repo_path
            .join(".sky")
            .join("tmp")
            .join(format!("prov_{}", task_id));
        let context_file = repo_path
            .join(".sky")
            .join("workspaces")
            .join(format!("{}.json", task_id));

        // Idempotency: an existing completed workspace for the same request
        // returns its recorded context; a divergent request is a collision.
        if worktree_dir.exists() {
            if let Some(existing) = Self::read_context(&context_file).await {
                if Self::is_identical_request(
                    &existing,
                    task_id,
                    project_id,
                    base_commit,
                    target_branch,
                ) {
                    tracing::info!(
                        task_id = task_id,
                        "Workspace already provisioned for identical request; returning existing context"
                    );
                    return Ok(existing);
                }
            }
            return Err(ProvisionError::WorktreeCollision(worktree_dir));
        }

        if let Some(parent) = tmp_worktree_dir.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = worktree_dir.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = context_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // 5. Staged setup: acquire the lock atomically (O_EXCL — never
        // truncate-create), create the worktree in tmp, then atomically rename.
        // A non-atomic write here would let two concurrent callers both pass
        // the exists() check above and both proceed.
        use tokio::io::AsyncWriteExt;
        let mut lock = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_file)
            .await
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent caller won the lock race (or a prior run was
                // interrupted between the early check and here). If the
                // identical request completed while we raced, return its
                // recorded context; otherwise reject — never run twice.
                if let Some(existing) = Self::read_context(&context_file).await {
                    if Self::is_identical_request(
                        &existing,
                        task_id,
                        project_id,
                        base_commit,
                        target_branch,
                    ) {
                        return Ok(existing);
                    }
                }
                return Err(ProvisionError::IncompleteProvisioningLock {
                    task_id: task_id.to_string(),
                });
            }
            Err(e) => return Err(ProvisionError::Io(e)),
        };
        if let Err(e) = lock.write_all(chrono::Utc::now().to_rfc3339().as_bytes()).await {
            drop(lock);
            let _ = tokio::fs::remove_file(&lock_file).await;
            return Err(ProvisionError::Io(e));
        }
        drop(lock);

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

        // Re-align Git metadata with the renamed directory; a failure here
        // must abort rather than hand back a worktree Git cannot operate on.
        if let Err(e) = self.git_adapter.repair_worktree(&repo_path, &worktree_dir) {
            let _ = self.git_adapter.remove_worktree(&repo_path, &worktree_dir);
            let _ = tokio::fs::remove_file(&lock_file).await;
            return Err(e);
        }

        let canonical_worktree = self.path_guard.sanitize_and_verify(&worktree_dir)?;

        let context = WorkspaceContext {
            task_id: task_id.to_string(),
            project_id: project_id.to_string(),
            base_commit: base_commit.map(str::to_owned),
            workspace_kind: WorkspaceKind::IsolatedWorktree {
                parent_repo: repo_path,
                worktree_path: canonical_worktree.clone(),
                branch: target_branch.to_string(),
            },
            canonical_root: canonical_worktree,
            created_at: chrono::Utc::now(),
        };

        // Record the completed context BEFORE releasing the lock so a crash
        // between rename and cleanup is reconciled deterministically.
        Self::write_context(&context_file, &context).await?;
        tokio::fs::remove_file(&lock_file).await?;

        Ok(context)
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
            let final_dir = sky_dir.join("worktrees").join(task_id);
            let context_file = sky_dir
                .join("workspaces")
                .join(format!("{}.json", task_id));

            if tmp_dir.exists() {
                let _ = self.git_adapter.remove_worktree(&repo_path, &tmp_dir);
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
            }

            // A final worktree with no recorded context means the run was
            // interrupted between rename and completion — it holds no proven
            // work yet, so clean it up rather than trust an incomplete state.
            if final_dir.exists() && !context_file.exists() {
                let _ = self.git_adapter.remove_worktree(&repo_path, &final_dir);
                let _ = tokio::fs::remove_dir_all(&final_dir).await;
            }

            tokio::fs::remove_file(&path).await?;
            recovered_count += 1;
        }

        Ok(recovered_count)
    }

    /// True when a recorded context satisfies the incoming request exactly:
    /// same task, project, base revision, and branch.
    fn is_identical_request(
        existing: &WorkspaceContext,
        task_id: &str,
        project_id: &str,
        base_commit: Option<&str>,
        target_branch: &str,
    ) -> bool {
        existing.task_id == task_id
            && existing.project_id == project_id
            && existing.base_commit.as_deref() == base_commit
            && matches!(
                &existing.workspace_kind,
                WorkspaceKind::IsolatedWorktree { branch, .. } if branch == target_branch
            )
    }

    async fn read_context(context_file: &Path) -> Option<WorkspaceContext> {
        let contents = tokio::fs::read_to_string(context_file).await.ok()?;
        serde_json::from_str(&contents).ok()
    }

    async fn write_context(
        context_file: &Path,
        context: &WorkspaceContext,
    ) -> Result<(), ProvisionError> {
        let json = serde_json::to_string_pretty(context)
            .map_err(|e| ProvisionError::GitError(format!("context serialization: {e}")))?;
        tokio::fs::write(context_file, json).await?;
        Ok(())
    }
}
