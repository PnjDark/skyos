use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Explicit policy for repositories with uncommitted work.
///
/// Zero-data-loss invariant: `git stash`, `git reset`, `git checkout -f`, and
/// any implicit cleanup are forbidden under every policy. An unsafe or
/// ambiguous state halts provisioning rather than risking data loss.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirtyTreePolicy {
    /// Strict: block provisioning if the working tree contains uncommitted
    /// changes.
    BlockOnDirty,
    /// Create the worktree from the requested base revision; leave the main
    /// working tree completely untouched.
    IsolateMainTreeUntouched,
    /// Snapshot untracked/staged changes into a temporary feature branch
    /// before attaching the worktree.
    SnapshotToBranch { branch_prefix: String },
}

/// Result of inspecting a repository's working-tree state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitStatusReport {
    pub active_branch: String,
    pub head_commit: String,
    pub staged_files: Vec<PathBuf>,
    pub unstaged_files: Vec<PathBuf>,
    pub untracked_files: Vec<PathBuf>,
    pub is_clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkspaceKind {
    DirectSandbox {
        path: PathBuf,
    },
    IsolatedWorktree {
        parent_repo: PathBuf,
        worktree_path: PathBuf,
        branch: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceContext {
    pub task_id: String,
    pub project_id: String,
    /// Base revision the worktree was created from (None = repository default).
    #[serde(default)]
    pub base_commit: Option<String>,
    pub workspace_kind: WorkspaceKind,
    pub canonical_root: PathBuf,
    pub created_at: DateTime<Utc>,
}
