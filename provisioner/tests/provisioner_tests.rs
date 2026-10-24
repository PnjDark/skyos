use skyos_provisioner::errors::ProvisionError;
use skyos_provisioner::models::{DirtyTreePolicy, GitStatusReport};
use skyos_provisioner::provisioner::{GitAdapter, RepositoryProvisioner};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

struct MockGitAdapter {
    pub is_dirty: bool,
}

impl GitAdapter for MockGitAdapter {
    fn inspect_status(&self, _repo_path: &Path) -> Result<GitStatusReport, ProvisionError> {
        if self.is_dirty {
            Ok(GitStatusReport {
                active_branch: "main".to_string(),
                head_commit: "abc1234".to_string(),
                staged_files: vec![PathBuf::from("src/lib.rs")],
                unstaged_files: vec![PathBuf::from("README.md")],
                untracked_files: vec![PathBuf::from("notes.txt")],
                is_clean: false,
            })
        } else {
            Ok(GitStatusReport {
                active_branch: "main".to_string(),
                head_commit: "abc1234".to_string(),
                staged_files: vec![],
                unstaged_files: vec![],
                untracked_files: vec![],
                is_clean: true,
            })
        }
    }

    fn create_worktree(
        &self,
        _repo: &Path,
        worktree_path: &Path,
        _branch: &str,
        _commit: Option<&str>,
    ) -> Result<(), ProvisionError> {
        std::fs::create_dir_all(worktree_path).map_err(ProvisionError::Io)?;
        std::fs::write(worktree_path.join("HEAD"), "ref: refs/heads/feature")
            .map_err(ProvisionError::Io)?;
        Ok(())
    }

    fn remove_worktree(
        &self,
        _repo: &Path,
        worktree_path: &Path,
    ) -> Result<(), ProvisionError> {
        if worktree_path.exists() {
            std::fs::remove_dir_all(worktree_path).map_err(ProvisionError::Io)?;
        }
        Ok(())
    }
}

fn adapter(is_dirty: bool) -> Arc<MockGitAdapter> {
    Arc::new(MockGitAdapter { is_dirty })
}

#[tokio::test]
async fn test_clean_repository_provisioning() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("my-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let ctx = provisioner
        .provision_workspace("task-101", "my-project", "feat/auth", None)
        .await
        .unwrap();

    assert_eq!(ctx.task_id, "task-101");
    assert!(ctx.canonical_root.exists());
    assert!(ctx.canonical_root.starts_with(sandbox));
    // Staged tmp dir and lock must not survive a successful run.
    assert!(!repo_dir.join(".sky/tmp/prov_task-101").exists());
    assert!(!repo_dir.join(".sky/provision_task-101.lock").exists());
}

#[tokio::test]
async fn test_dirty_repository_block_policy() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("dirty-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

    let provisioner =
        RepositoryProvisioner::new(sandbox, adapter(true), DirtyTreePolicy::BlockOnDirty).unwrap();

    let res = provisioner
        .provision_workspace("task-102", "dirty-project", "feat/payment", None)
        .await;

    match res {
        Err(ProvisionError::DirtyTreePolicyBlock {
            staged,
            unstaged,
            untracked,
        }) => {
            assert_eq!(staged, 1);
            assert_eq!(unstaged, 1);
            assert_eq!(untracked, 1);
        }
        other => panic!("Expected DirtyTreePolicyBlock, got {other:?}"),
    }
    // Block policy must not create any worktree or lock.
    assert!(!repo_dir.join(".sky/worktrees/task-102").exists());
    assert!(!repo_dir.join(".sky/provision_task-102.lock").exists());
}

#[tokio::test]
async fn test_dirty_repository_isolate_policy_leaves_main_tree_untouched() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("isolate-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();
    // Simulate an uncommitted user file in the main tree.
    std::fs::write(repo_dir.join("uncommitted.txt"), b"user work").unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(true),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let ctx = provisioner
        .provision_workspace("task-104", "isolate-project", "feat/x", None)
        .await
        .unwrap();

    assert!(ctx.canonical_root.exists());
    // Zero-loss invariant: the uncommitted file is untouched.
    assert_eq!(
        std::fs::read(repo_dir.join("uncommitted.txt")).unwrap(),
        b"user work"
    );
}

#[tokio::test]
async fn test_path_traversal_rejection() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let res = provisioner
        .provision_workspace("task-103", "../outside-project", "feat/hack", None)
        .await;

    assert!(matches!(res, Err(ProvisionError::PathTraversalViolation { .. })));
}

#[cfg(unix)]
#[tokio::test]
async fn test_symlink_escape_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let outside = TempDir::new().unwrap();
    std::fs::create_dir_all(outside.path().join("evil/.git")).unwrap();
    // Symlink inside the sandbox pointing to a repo outside it.
    symlink(outside.path().join("evil"), sandbox.join("linked-project")).unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let res = provisioner
        .provision_workspace("task-105", "linked-project", "feat/escape", None)
        .await;

    assert!(matches!(
        res,
        Err(ProvisionError::SymlinkEscape { .. })
            | Err(ProvisionError::PathTraversalViolation { .. })
    ));
}

#[tokio::test]
async fn test_worktree_collision_detected() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("collision-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    provisioner
        .provision_workspace("task-106", "collision-project", "feat/a", None)
        .await
        .unwrap();

    let second = provisioner
        .provision_workspace("task-106", "collision-project", "feat/b", None)
        .await;
    assert!(matches!(second, Err(ProvisionError::WorktreeCollision(_))));
}

#[tokio::test]
async fn test_interrupted_provisioning_recovery() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("recovery-project");
    let sky_dir = repo_dir.join(".sky");
    let tmp_dir = sky_dir.join("tmp").join("prov_task-999");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();
    std::fs::create_dir_all(&tmp_dir).unwrap();
    std::fs::write(sky_dir.join("provision_task-999.lock"), "2026-10-23T07:00:00Z").unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let recovered = provisioner
        .recover_interrupted_provisioning("recovery-project")
        .await
        .unwrap();

    assert_eq!(recovered, 1);
    assert!(!tmp_dir.exists());
    assert!(!sky_dir.join("provision_task-999.lock").exists());
}

#[tokio::test]
async fn test_repeated_requests_do_not_duplicate_or_corrupt() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("repeat-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let first = provisioner
        .provision_workspace("task-107", "repeat-project", "feat/one", None)
        .await
        .unwrap();
    let second = provisioner
        .provision_workspace("task-108", "repeat-project", "feat/two", None)
        .await
        .unwrap();

    assert_ne!(first.canonical_root, second.canonical_root);
    assert!(first.canonical_root.exists());
    assert!(second.canonical_root.exists());

    // Recovery on a healthy tree is a no-op.
    let recovered = provisioner
        .recover_interrupted_provisioning("repeat-project")
        .await
        .unwrap();
    assert_eq!(recovered, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_duplicate_requests_create_single_worktree() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();
    let repo_dir = sandbox.join("race-project");
    std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

    let provisioner = Arc::new(
        RepositoryProvisioner::new(
            sandbox,
            adapter(false),
            DirtyTreePolicy::IsolateMainTreeUntouched,
        )
        .unwrap(),
    );

    // Two callers race the identical request concurrently.
    let p1 = {
        let p = Arc::clone(&provisioner);
        async move { p.provision_workspace("task-race", "race-project", "feat/race", None).await }
    };
    let p2 = {
        let p = Arc::clone(&provisioner);
        async move { p.provision_workspace("task-race", "race-project", "feat/race", None).await }
    };
    let (r1, r2) = tokio::join!(p1, p2);

    // Exactly one worktree must exist regardless of who won the lock race.
    let worktree_dir = repo_dir.join(".sky/worktrees/task-race");
    assert!(worktree_dir.exists());
    let count = std::fs::read_dir(repo_dir.join(".sky/worktrees")).unwrap().count();
    assert_eq!(count, 1, "duplicate worktrees created under concurrency");
    // Lock must be released by the winner; no staged tmp dir left behind.
    assert!(!repo_dir.join(".sky/provision_task-race.lock").exists());
    assert!(!repo_dir.join(".sky/tmp/prov_task-race").exists());

    // Outcomes: winner succeeds; the loser either observes the identical
    // completed context (if it arrived after the context file was written)
    // or is rejected with IncompleteProvisioningLock. Never both succeed
    // with different contexts, and never both fail leaving no workspace.
    match (r1, r2) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.canonical_root, b.canonical_root);
            assert_eq!(a.created_at, b.created_at);
        }
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => {
            assert!(
                matches!(e, ProvisionError::IncompleteProvisioningLock { .. }),
                "loser must be rejected by the lock, got: {e}"
            );
        }
        (Err(e1), Err(e2)) => panic!(
            "both concurrent callers failed: {e1} / {e2}"
        ),
    }
}

#[tokio::test]
async fn test_repository_not_found() {
    let temp = TempDir::new().unwrap();
    let sandbox = temp.path();

    let provisioner = RepositoryProvisioner::new(
        sandbox,
        adapter(false),
        DirtyTreePolicy::IsolateMainTreeUntouched,
    )
    .unwrap();

    let res = provisioner
        .provision_workspace("task-109", "missing-repo", "feat/none", None)
        .await;
    assert!(matches!(res, Err(ProvisionError::RepositoryNotFound(_))));
}
