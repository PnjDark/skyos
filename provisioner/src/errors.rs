use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProvisionError {
    #[error("Path traversal violation: Target '{target}' is outside sandbox root '{sandbox_root}'")]
    PathTraversalViolation {
        target: std::path::PathBuf,
        sandbox_root: std::path::PathBuf,
    },

    #[error("Symlink escape detected: '{path}' targets outside workspace sandbox")]
    SymlinkEscape { path: std::path::PathBuf },

    #[error("Repository not found at canonical path '{0}'")]
    RepositoryNotFound(std::path::PathBuf),

    #[error(
        "Dirty working tree cannot be safely captured under current policy. \
         Staged: {staged}, Unstaged: {unstaged}, Untracked: {untracked}"
    )]
    DirtyTreePolicyBlock {
        staged: usize,
        unstaged: usize,
        untracked: usize,
    },

    #[error("Worktree collision: Worktree already exists at '{0}'")]
    WorktreeCollision(std::path::PathBuf),

    #[error("Permission denied by kernel policy: {0}")]
    PermissionDenied(String),

    #[error("Git execution error: {0}")]
    GitError(String),

    #[error("IO failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Provisioning lock exists for task '{task_id}': Incomplete operation detected; run recovery first")]
    IncompleteProvisioningLock { task_id: String },

    #[error(
        "Dirty-tree policy '{policy}' is not implemented; refusing to proceed as if it were"
    )]
    UnimplementedPolicy { policy: String },

    #[error("Task '{0}' is not registered in the runtime ledger")]
    TaskNotFound(String),
}
