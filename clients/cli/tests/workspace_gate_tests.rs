//! Phase 3A integration-gate tests.
//!
//! Verifies the *governed* provisioning path end to end against real kernel
//! components (`TaskStore`, `EventBus`, `GrantIssuer`, `PolicyEngine`) with a
//! mock Git adapter so no real repository is required.

use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{Capability, CapabilityGrant};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use sky_cli::workspace::{
    GovernedProvisioner, ProvisionRequest, EVENT_WORKSPACE_PROVISIONED,
    EVENT_WORKSPACE_PROVISIONING_FAILED, EVENT_WORKSPACE_PROVISIONING_RECOVERED,
    EVENT_WORKSPACE_PROVISIONING_STARTED,
};
use skyos_provisioner::errors::ProvisionError;
use skyos_provisioner::models::{DirtyTreePolicy, GitStatusReport};
use skyos_provisioner::provisioner::GitAdapter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

// ── Mock Git adapter ──────────────────────────────────────────────────────────

struct MockGit {
    dirty: bool,
}

impl GitAdapter for MockGit {
    fn inspect_status(&self, _repo: &Path) -> Result<GitStatusReport, ProvisionError> {
        Ok(GitStatusReport {
            active_branch: "main".into(),
            head_commit: "abc1234".into(),
            staged_files: if self.dirty {
                vec![PathBuf::from("a.rs")]
            } else {
                vec![]
            },
            unstaged_files: vec![],
            untracked_files: if self.dirty {
                vec![PathBuf::from("n.txt")]
            } else {
                vec![]
            },
            is_clean: !self.dirty,
        })
    }

    fn create_worktree(
        &self,
        _repo: &Path,
        worktree_path: &Path,
        _branch: &str,
        _commit: Option<&str>,
    ) -> Result<(), ProvisionError> {
        std::fs::create_dir_all(worktree_path).map_err(ProvisionError::Io)?;
        std::fs::write(worktree_path.join("HEAD"), "mock").map_err(ProvisionError::Io)?;
        Ok(())
    }

    fn remove_worktree(&self, _repo: &Path, worktree_path: &Path) -> Result<(), ProvisionError> {
        if worktree_path.exists() {
            std::fs::remove_dir_all(worktree_path).map_err(ProvisionError::Io)?;
        }
        Ok(())
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

struct Harness {
    _temp: TempDir,
    sandbox: PathBuf,
    db_dir: PathBuf,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
    dirty: bool,
}

impl Harness {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let sandbox = temp.path().join("sandbox");
        let db_dir = temp.path().join("db");
        std::fs::create_dir_all(&sandbox).unwrap();

        let db_path = db_dir.join("runtime_state.db");
        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        let grant_issuer = GrantIssuer::new();

        Self {
            _temp: temp,
            sandbox,
            db_dir,
            task_store,
            event_bus,
            grant_issuer,
            dirty: false,
        }
    }

    fn make_repo(&self, name: &str) -> PathBuf {
        let repo = self.sandbox.join(name);
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        repo
    }

    fn new_task(&self) -> Uuid {
        self.task_store
            .create_task("gate task", TaskState::Created, 1)
            .unwrap()
    }

    /// Grant covering both required capabilities for a project directory.
    fn grant_for(&self, task_id: Uuid, project_path: &Path) -> CapabilityGrant {
        self.grant_issuer.issue_grant(
            "test",
            task_id,
            vec![
                Capability::GitWrite {
                    repo_root: project_path.to_path_buf(),
                },
                Capability::FileSystemWrite {
                    root: project_path.to_path_buf(),
                },
            ],
            None,
        )
    }

    fn provisioner(&self) -> GovernedProvisioner<'_> {
        GovernedProvisioner::new(
            &self.task_store,
            &self.event_bus,
            Arc::new(MockGit { dirty: self.dirty }),
        )
    }

    fn events(&self, task_id: Option<Uuid>) -> Vec<kernel::events::Event> {
        match task_id {
            Some(id) => self.event_bus.get_events_for_task(&id.to_string()).unwrap(),
            None => Vec::new(),
        }
    }

    fn event_types(&self, task_id: Uuid) -> Vec<String> {
        self.events(Some(task_id))
            .into_iter()
            .map(|e| e.event_type)
            .collect()
    }
}

fn request<'a>(task_id: Uuid, project_id: &'a str) -> ProvisionRequest<'a> {
    ProvisionRequest {
        task_id,
        project_id,
        target_branch: "feat/gate",
        base_commit: None,
        dirty_policy: DirtyTreePolicy::IsolateMainTreeUntouched,
    }
}

// ── WP1: authorization ────────────────────────────────────────────────────────

#[tokio::test]
async fn unauthorized_missing_capability_fails_closed_before_mutation() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();

    // Grant only GitWrite — missing the FileSystemWrite half.
    let grant = h.grant_issuer.issue_grant(
        "test",
        task_id,
        vec![Capability::GitWrite {
            repo_root: repo.clone(),
        }],
        None,
    );

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap_err();

    assert!(matches!(err, ProvisionError::PermissionDenied(_)));
    // No workspace was created.
    assert!(!repo.join(".sky/worktrees").exists());
    // Ledger records the denial chain: PermissionDenied + Failed(stage=authorization).
    let types = h.event_types(task_id);
    assert!(types.contains(&"PermissionDenied".to_string()));
    assert!(types.contains(&EVENT_WORKSPACE_PROVISIONING_FAILED.to_string()));
    // Started must NOT be emitted for a denied request.
    assert!(!types.contains(&EVENT_WORKSPACE_PROVISIONING_STARTED.to_string()));
}

#[tokio::test]
async fn grant_scoped_to_other_project_is_rejected() {
    let h = Harness::new();
    h.make_repo("proj-a");
    let other = h.make_repo("proj-b");
    let task_id = h.new_task();

    let grant = h.grant_for(task_id, &other);

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj-a"), &grant)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::PermissionDenied(_)));
    assert!(!h.sandbox.join("proj-a/.sky/worktrees").exists());
}

#[tokio::test]
async fn unknown_task_is_rejected_before_authorization() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let ghost = Uuid::new_v4();
    let grant = h.grant_for(ghost, &repo);

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(ghost, "proj"), &grant)
        .await
        .unwrap_err();

    assert!(matches!(err, ProvisionError::TaskNotFound(_)));
    assert!(!repo.join(".sky/worktrees").exists());
}

// ── WP2: lifecycle ledger events ──────────────────────────────────────────────

#[tokio::test]
async fn authorized_provision_emits_started_and_provisioned() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    let ctx = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap();

    assert!(ctx.canonical_root.exists());
    let types = h.event_types(task_id);
    let start = types
        .iter()
        .position(|t| t == EVENT_WORKSPACE_PROVISIONING_STARTED)
        .expect("started event missing");
    let done = types
        .iter()
        .position(|t| t == EVENT_WORKSPACE_PROVISIONED)
        .expect("provisioned event missing");
    // Started must precede Provisioned.
    assert!(start < done);
    // Authorization audit must also exist.
    assert!(types.contains(&"PermissionGranted".to_string()));
}

#[tokio::test]
async fn execution_failure_emits_failed_with_execution_stage() {
    let mut h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    // Dirty tree + block policy → execution-stage failure after authorization.
    h.dirty = true;
    let mut req = request(task_id, "proj");
    req.dirty_policy = DirtyTreePolicy::BlockOnDirty;

    let err = h.provisioner().provision(&h.sandbox, &req, &grant).await;
    assert!(matches!(
        err,
        Err(ProvisionError::DirtyTreePolicyBlock { .. })
    ));

    let events = h.events(Some(task_id));
    let failed = events
        .iter()
        .find(|e| e.event_type == EVENT_WORKSPACE_PROVISIONING_FAILED)
        .expect("failed event missing");
    assert_eq!(failed.payload.get("stage").and_then(|v| v.as_str()), Some("execution"));
    // Started WAS emitted (authorization passed), then failed.
    let types = h.event_types(task_id);
    assert!(types.contains(&EVENT_WORKSPACE_PROVISIONING_STARTED.to_string()));
}

// ── WP4: idempotency & recovery ───────────────────────────────────────────────

#[tokio::test]
async fn repeated_identical_request_returns_same_workspace() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    let first = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap();
    let second = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap();

    assert_eq!(first.canonical_root, second.canonical_root);
    assert_eq!(first.created_at, second.created_at);
    // Exactly one worktree directory exists.
    let count = std::fs::read_dir(repo.join(".sky/worktrees")).unwrap().count();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn divergent_request_for_same_task_is_a_collision() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    h.provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap();

    let mut divergent = request(task_id, "proj");
    divergent.target_branch = "feat/other-branch";
    let err = h
        .provisioner()
        .provision(&h.sandbox, &divergent, &grant)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::WorktreeCollision(_)));
}

#[tokio::test]
async fn interrupted_provisioning_blocks_then_recovers() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();

    // Simulate an interrupted run: staged tmp dir + lock, no context file.
    let sky = repo.join(".sky");
    let tmp = sky.join("tmp").join(format!("prov_{}", task_id));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(sky.join(format!("provision_{}.lock", task_id)), "ts").unwrap();

    // Provisioning must refuse while the lock exists (fail closed).
    let grant = h.grant_for(task_id, &repo);
    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::IncompleteProvisioningLock { .. }));

    // Recovery cleans the incomplete state.
    let recovered = h.provisioner().recover(&h.sandbox, "proj").await.unwrap();
    assert_eq!(recovered, 1);
    assert!(!tmp.exists());
    assert!(!sky.join(format!("provision_{}.lock", task_id)).exists());

    // After recovery the same request succeeds.
    let ctx = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await
        .unwrap();
    assert!(ctx.canonical_root.exists());
}

#[tokio::test]
async fn recovery_emits_durable_audit_event() {
    let h = Harness::new();
    h.make_repo("proj");

    let count = h.provisioner().recover(&h.sandbox, "proj").await.unwrap();
    assert_eq!(count, 0);

    // Recovery events carry no task correlation, so scan the raw ledger
    // directly to prove the record is durably persisted.
    let conn = rusqlite::Connection::open(h.db_dir.join("runtime_state.db")).unwrap();
    let stored: Option<(String, String)> = conn
        .query_row(
            "SELECT event_type, payload FROM events \
             WHERE event_type = 'WorkspaceProvisioningRecovered' \
             ORDER BY created_at DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    let (event_type, payload) = stored.expect("recovery event not found in ledger");
    assert_eq!(event_type, EVENT_WORKSPACE_PROVISIONING_RECOVERED);
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["project_id"], "proj");
    assert_eq!(payload["recovered_count"], 0);
}

// ── WP6: ledger-failure transaction safety ──────────────────────────────────

#[tokio::test]
async fn ledger_failure_before_mutation_prevents_any_disk_change() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    // Make EVERY ledger write fail: drop the events table under the runtime.
    let conn = rusqlite::Connection::open(h.db_dir.join("runtime_state.db")).unwrap();
    conn.execute_batch("DROP TABLE IF EXISTS events;").unwrap();

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await;
    assert!(err.is_err(), "unauditable operation must not succeed");
    // Fail closed: no workspace, no lock, no staged tmp dir on disk.
    assert!(!repo.join(".sky/worktrees").exists());
    assert!(!repo.join(".sky/provision_".to_string() + &task_id.to_string() + ".lock").exists());
    assert!(!repo.join(".sky/tmp").exists());
}

#[tokio::test]
async fn final_ledger_failure_rolls_back_completed_workspace() {
    let h = Harness::new();
    let repo = h.make_repo("proj");
    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &repo);

    // Allow Started/permission events but reject exactly the final
    // WorkspaceProvisioned write, simulating a ledger failure after the
    // worktree already exists on disk.
    let conn = rusqlite::Connection::open(h.db_dir.join("runtime_state.db")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER deny_provisioned BEFORE INSERT ON events
         WHEN NEW.event_type = 'WorkspaceProvisioned'
         BEGIN SELECT RAISE(ABORT, 'injected ledger failure'); END;",
    )
    .unwrap();

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "proj"), &grant)
        .await;
    assert!(err.is_err(), "failed final audit write must fail the operation");

    // Rollback: no partially published (unaudited) workspace may remain.
    let worktrees = repo.join(".sky/worktrees");
    if worktrees.exists() {
        assert_eq!(
            std::fs::read_dir(&worktrees).unwrap().count(),
            0,
            "workspace must be rolled back when its success event cannot be recorded"
        );
    }
    let context_file = repo
        .join(".sky/workspaces")
        .join(format!("{}.json", task_id));
    assert!(!context_file.exists(), "context file must be rolled back too");
    // And crucially, the ledger holds no WorkspaceProvisioned success event.
    let types = h.event_types(task_id);
    assert!(!types.contains(&EVENT_WORKSPACE_PROVISIONED.to_string()));
    assert!(types.contains(&EVENT_WORKSPACE_PROVISIONING_STARTED.to_string()));
}

// ── WP5: path security ────────────────────────────────────────────────────────

#[tokio::test]
async fn traversal_project_id_rejected_without_mutation() {
    let h = Harness::new();
    let task_id = h.new_task();
    let ghost_repo = h.sandbox.join("outside");
    std::fs::create_dir_all(ghost_repo.join(".git")).unwrap();
    let grant = h.grant_for(task_id, &ghost_repo);

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "../outside"), &grant)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ProvisionError::PathTraversalViolation { .. } | ProvisionError::PermissionDenied(_)
    ));
    assert!(!ghost_repo.join(".sky/worktrees").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_rejected_through_governed_path() {
    use std::os::unix::fs::symlink;

    let h = Harness::new();
    let outside = TempDir::new().unwrap();
    std::fs::create_dir_all(outside.path().join("evil/.git")).unwrap();
    symlink(outside.path().join("evil"), h.sandbox.join("linked")).unwrap();

    let task_id = h.new_task();
    let grant = h.grant_for(task_id, &h.sandbox.join("linked"));

    let err = h
        .provisioner()
        .provision(&h.sandbox, &request(task_id, "linked"), &grant)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ProvisionError::SymlinkEscape { .. } | ProvisionError::PathTraversalViolation { .. }
    ));
}
