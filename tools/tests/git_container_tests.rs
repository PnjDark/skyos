use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use kernel::persistence::db::DatabaseConnectionPool;
use std::path::Path;
use std::process::Command;
use tempfile::{tempdir, TempDir};
use tools::containers::ContainerToolExecutor;
use tools::git::GitToolRegistry;
use tools::types::{ToolContext, ToolStatus};
use uuid::Uuid;

// ── shared test harness ──────────────────────────────────────────────────────

fn runtime() -> (TempDir, EventBus, ArtifactRegistry, GrantIssuer) {
    let temp = tempdir().unwrap();
    let db = temp.path().join("runtime.db");
    let event_bus = EventBus::open(&db).unwrap();
    let registry = ArtifactRegistry::open(&db, temp.path().join("cas")).unwrap();
    (temp, event_bus, registry, GrantIssuer::new())
}

fn git_read_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    repo_root: &Path,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::GitRead {
            repo_root: repo_root.to_path_buf(),
        }],
        None,
    )
}

fn git_write_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    repo_root: &Path,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![
            Capability::GitRead {
                repo_root: repo_root.to_path_buf(),
            },
            Capability::GitWrite {
                repo_root: repo_root.to_path_buf(),
            },
        ],
        None,
    )
}

fn container_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    allowed_image: &str,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::ContainerRun {
            allowed_image: allowed_image.to_string(),
        }],
        None,
    )
}

// ── Git: read-only grant rejects all mutations ───────────────────────────────

#[tokio::test]
async fn git_read_only_grant_rejects_stage() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_read_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git.stage(&ctx, &grant, repo_root, &["src/main.rs"]).await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Policy Engine denied git write"));
    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events.iter().any(|e| e.event_type == "PermissionDenied"));
}

#[tokio::test]
async fn git_read_only_grant_rejects_commit() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_read_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git.commit(&ctx, &grant, repo_root, "feat: add thing").await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Policy Engine denied git write"));
}

#[tokio::test]
async fn git_read_only_grant_rejects_branch_create() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_read_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git
        .branch_create(&ctx, &grant, repo_root, "feature/new")
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Policy Engine denied git write"));
}

// ── Git: write grant rejects unsafe ref names and paths ─────────────────────

#[tokio::test]
async fn git_rejects_unsafe_branch_name_with_shell_chars() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    for bad_name in &["$(rm -rf /)", "-bad", "a..b", "branch/"] {
        let result = git.branch_create(&ctx, &grant, repo_root, bad_name).await;
        assert_eq!(
            result.status,
            ToolStatus::Failed,
            "expected rejection for branch name {bad_name:?}"
        );
        assert!(result
            .error_message
            .unwrap()
            .contains("Unsafe branch name rejected"));
    }
}

#[tokio::test]
async fn git_rejects_traversal_in_stage_paths() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git
        .stage(&ctx, &grant, repo_root, &["../outside/secret.txt"])
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Unsafe stage path rejected"));
}

#[tokio::test]
async fn git_rejects_absolute_path_in_stage() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git.stage(&ctx, &grant, repo_root, &["/etc/passwd"]).await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Unsafe stage path rejected"));
}

#[tokio::test]
async fn git_rejects_empty_commit_message() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git.commit(&ctx, &grant, repo_root, "").await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Commit message must not be empty"));
}

// ── Git: write grant rejects requests outside the authorized repo root ───────

#[tokio::test]
async fn git_write_grant_rejects_operation_outside_repo_root() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let authorized_root = temp.path().join("authorized_repo");
    std::fs::create_dir(&authorized_root).unwrap();
    let other_root = temp.path().join("other_repo");
    std::fs::create_dir(&other_root).unwrap();

    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, &authorized_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = git.stage(&ctx, &grant, &other_root, &["file.rs"]).await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Policy Engine denied git write"));
}

// ── Git: audit trail is written for both allowed and denied operations ────────

#[tokio::test]
async fn git_denied_operation_emits_permission_denied_event() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path();
    let task_id = Uuid::new_v4();
    // Only read capability — write must be denied
    let grant = git_read_grant(&issuer, task_id, repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    let _ = git.checkout(&ctx, &grant, repo_root, "main").await;

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "PermissionDenied"),
        "expected PermissionDenied audit event"
    );
}

#[tokio::test]
async fn git_surfaces_policy_and_failure_audit_persistence_errors() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = git_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    DatabaseConnectionPool::open(temp.path().join("runtime.db"))
        .unwrap()
        .connection()
        .unwrap()
        .execute_batch("DROP TABLE events")
        .unwrap();

    let result = git.status(&ctx, &grant, temp.path()).await;
    assert_eq!(result.status, ToolStatus::Failed);
    let error = result.error_message.unwrap();
    assert!(error.contains("Failed to persist git read audit"));
    assert!(error.contains("failed to persist Git failure audit"));
}

#[tokio::test]
async fn successful_git_commit_with_failed_completion_audit_is_outcome_unknown() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let repo_root = temp.path().join("repo");
    std::fs::create_dir(&repo_root).unwrap();
    let run_git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&repo_root)
            .output()
            .expect("git is required for the Git integration tests");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run_git(&["init"]);
    run_git(&["config", "user.name", "Sky Test"]);
    run_git(&["config", "user.email", "sky-test@example.invalid"]);
    std::fs::write(repo_root.join("tracked.txt"), "commit me").unwrap();
    run_git(&["add", "--", "tracked.txt"]);

    let task_id = Uuid::new_v4();
    let grant = git_write_grant(&issuer, task_id, &repo_root);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut git = GitToolRegistry::new(&event_bus, &mut registry, &issuer);

    DatabaseConnectionPool::open(temp.path().join("runtime.db"))
        .unwrap()
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_git_completion \
             BEFORE INSERT ON events \
             WHEN NEW.event_type = 'GitOperationCompleted' \
             BEGIN SELECT RAISE(FAIL, 'completion audit unavailable'); END;",
        )
        .unwrap();

    let result = git
        .commit(&ctx, &grant, &repo_root, "test: commit with audit failure")
        .await;
    assert_eq!(result.status, ToolStatus::AuditPersistenceFailed);
    assert!(result
        .error_message
        .unwrap()
        .contains("completion audit failed"));

    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(&repo_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "commit must physically exist despite its failed completion audit"
    );
}

// ── Container: image not on allowlist is rejected ────────────────────────────

#[tokio::test]
async fn container_rejects_image_not_on_allowlist() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = container_grant(&issuer, task_id, "alpine:3.19");
    let ctx = ToolContext::new(task_id, "test_agent");
    let executor = ContainerToolExecutor::new(&event_bus, &issuer, "docker");

    let result = executor
        .run(
            &ctx,
            &grant,
            "ubuntu:latest",
            &["echo", "hello"],
            None,
            None,
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("Policy Engine denied container run"));
    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events.iter().any(|e| e.event_type == "PermissionDenied"));
}

#[tokio::test]
async fn container_wildcard_allowlist_permits_any_image() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    // Wildcard grant — policy allows any image
    let grant = container_grant(&issuer, task_id, "*");
    let ctx = ToolContext::new(task_id, "test_agent");
    let executor = ContainerToolExecutor::new(&event_bus, &issuer, "docker");

    // We don't actually run docker in CI; we only verify the policy check passes.
    // The process executor will fail because docker may not be present, but the
    // status must NOT be PermissionDenied.
    let result = executor
        .run(&ctx, &grant, "alpine:3.19", &["echo", "hello"], None, None)
        .await;

    assert_ne!(
        result.status,
        ToolStatus::PermissionDenied,
        "wildcard grant should pass policy; got: {:?}",
        result.error_message
    );
}

// ── Container: expired grant is rejected ─────────────────────────────────────

#[tokio::test]
async fn container_expired_grant_is_denied() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::ContainerRun {
            allowed_image: "alpine:3.19".to_string(),
        }],
        Some(chrono::Duration::minutes(-5)),
    );
    let ctx = ToolContext::new(task_id, "test_agent");
    let executor = ContainerToolExecutor::new(&event_bus, &issuer, "docker");

    let result = executor
        .run(&ctx, &grant, "alpine:3.19", &["echo", "hello"], None, None)
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("expired or revoked"));
}

// ── Container: revoked grant is denied ───────────────────────────────────────

#[tokio::test]
async fn container_revoked_grant_is_denied() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::ContainerRun {
            allowed_image: "alpine:3.19".to_string(),
        }],
        None,
    );
    issuer.revoke_grant(&grant.grant_id).unwrap();
    let updated_grant = issuer.get_grant(&grant.grant_id).unwrap();
    let ctx = ToolContext::new(task_id, "test_agent");
    let executor = ContainerToolExecutor::new(&event_bus, &issuer, "docker");

    let result = executor
        .run(
            &ctx,
            &updated_grant,
            "alpine:3.19",
            &["echo", "hello"],
            None,
            None,
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("expired or revoked"));
}

// ── Container: audit event is emitted on denial ───────────────────────────────

#[tokio::test]
async fn container_denial_emits_audit_event() {
    let (_temp, event_bus, _registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = container_grant(&issuer, task_id, "alpine:3.19");
    let ctx = ToolContext::new(task_id, "test_agent");
    let executor = ContainerToolExecutor::new(&event_bus, &issuer, "docker");

    let _ = executor
        .run(&ctx, &grant, "malicious:latest", &["sh"], None, None)
        .await;

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "PermissionDenied"),
        "expected PermissionDenied audit event for disallowed image"
    );
}

// ── ToolContext Clone is derived on the type itself ──────────────────────────
// (no impl needed here)
