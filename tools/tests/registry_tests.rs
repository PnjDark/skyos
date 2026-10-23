use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use tempfile::{tempdir, TempDir};
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolStatus};
use uuid::Uuid;

// ── harness ──────────────────────────────────────────────────────────────────

fn runtime() -> (TempDir, EventBus, ArtifactRegistry, GrantIssuer) {
    let temp = tempdir().unwrap();
    let db = temp.path().join("runtime.db");
    let event_bus = EventBus::open(&db).unwrap();
    let registry = ArtifactRegistry::open(&db, temp.path().join("cas")).unwrap();
    (temp, event_bus, registry, GrantIssuer::new())
}

fn fs_read_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    root: &std::path::Path,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::FileSystemRead {
            root: root.canonicalize().unwrap(),
        }],
        None,
    )
}

fn fs_write_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    root: &std::path::Path,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::FileSystemWrite {
            root: root.canonicalize().unwrap(),
        }],
        None,
    )
}

fn req(tool_id: &str, operation_id: &str, params: serde_json::Value) -> InvocationRequest {
    InvocationRequest {
        tool_id: tool_id.to_string(),
        operation_id: operation_id.to_string(),
        parameters: params,
        idempotency_key: None,
    }
}

// ── unknown tool / operation ──────────────────────────────────────────────────

#[tokio::test]
async fn dispatcher_rejects_unknown_tool_id() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("database", "query", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown tool_id"));
}

#[tokio::test]
async fn dispatcher_rejects_unknown_filesystem_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("filesystem", "delete_file", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

#[tokio::test]
async fn dispatcher_rejects_unknown_git_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        Uuid::new_v4(),
        vec![Capability::GitRead {
            repo_root: temp.path().to_path_buf(),
        }],
        None,
    );
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("git", "rebase", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

#[tokio::test]
async fn dispatcher_rejects_unknown_process_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("process", "spawn_shell", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

#[tokio::test]
async fn dispatcher_rejects_unknown_container_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        Uuid::new_v4(),
        vec![Capability::ContainerRun {
            allowed_image: "*".to_string(),
        }],
        None,
    );
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("container", "build", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

// ── missing / wrong-type parameters ──────────────────────────────────────────

#[tokio::test]
async fn dispatcher_rejects_missing_relative_path_for_read() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("filesystem", "read_file", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("relative_path"));
}

#[tokio::test]
async fn dispatcher_rejects_missing_content_for_write() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_write_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "filesystem",
                "write_file",
                serde_json::json!({"relative_path": "out.txt"}),
            ),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("content"));
}

#[tokio::test]
async fn dispatcher_rejects_non_string_args_array_for_process() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_read_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "process",
                "execute",
                serde_json::json!({"program": "echo", "args": [1, 2, 3]}),
            ),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("args"));
}

#[tokio::test]
async fn dispatcher_rejects_missing_message_for_git_commit() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::GitWrite {
            repo_root: temp.path().to_path_buf(),
        }],
        None,
    );
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req("git", "commit", serde_json::json!({})),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("message"));
}

// ── grant expiry / revocation ─────────────────────────────────────────────────

#[tokio::test]
async fn dispatcher_rejects_expired_grant_for_filesystem_read() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::FileSystemRead {
            root: temp.path().canonicalize().unwrap(),
        }],
        Some(chrono::Duration::minutes(-5)),
    );
    std::fs::write(temp.path().join("file.txt"), b"data").unwrap();
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "filesystem",
                "read_file",
                serde_json::json!({"relative_path": "file.txt"}),
            ),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::PermissionDenied);
}

#[tokio::test]
async fn dispatcher_rejects_revoked_grant_for_filesystem_write() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::FileSystemWrite {
            root: temp.path().canonicalize().unwrap(),
        }],
        None,
    );
    issuer.revoke_grant(&grant.grant_id).unwrap();
    let revoked = issuer.get_grant(&grant.grant_id).unwrap();
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &revoked,
            req(
                "filesystem",
                "write_file",
                serde_json::json!({"relative_path": "out.txt", "content": "x"}),
            ),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::PermissionDenied);
}

// ── scope mismatch: valid grant for a different root ─────────────────────────

#[tokio::test]
async fn dispatcher_rejects_grant_scoped_to_different_workspace() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let authorized = temp.path().join("authorized");
    let other = temp.path().join("other");
    std::fs::create_dir_all(&authorized).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("secret.txt"), b"secret").unwrap();

    let task_id = Uuid::new_v4();
    // Grant is for `authorized`, request targets `other`
    let grant = fs_read_grant(&issuer, task_id, &authorized);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "filesystem",
                "read_file",
                serde_json::json!({"relative_path": "secret.txt"}),
            ),
            &other,
        )
        .await;

    assert_eq!(result.status, ToolStatus::PermissionDenied);
}

// ── successful dispatch produces a result and audit event ────────────────────

#[tokio::test]
async fn dispatcher_routes_filesystem_write_and_emits_audit_event() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_write_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "filesystem",
                "write_file",
                serde_json::json!({"relative_path": "hello.txt", "content": "hello dispatcher"}),
            ),
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Succeeded);
    assert!(result.artifact.is_some());
    assert!(std::fs::read(temp.path().join("hello.txt")).unwrap() == b"hello dispatcher");

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events.iter().any(|e| e.event_type == "PermissionGranted"));
    assert!(events
        .iter()
        .any(|e| e.event_type == "ToolExecutionCompleted"));
}

// ── audit correlation contract ───────────────────────────────────────────────

#[tokio::test]
async fn dispatcher_emits_tool_invocation_attempted_event() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_write_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    dispatcher
        .dispatch(
            &ctx,
            &grant,
            req(
                "filesystem",
                "write_file",
                serde_json::json!({"relative_path": "audit.txt", "content": "x"}),
            ),
            temp.path(),
        )
        .await;

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|e| e.event_type == "ToolInvocationAttempted"));
}

#[tokio::test]
async fn dispatcher_records_idempotency_key_in_attempted_event() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = fs_write_grant(&issuer, task_id, temp.path());
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let request = InvocationRequest {
        tool_id: "filesystem".into(),
        operation_id: "write_file".into(),
        parameters: serde_json::json!({"relative_path": "idem.txt", "content": "y"}),
        idempotency_key: Some("op-abc-123".to_string()),
    };

    dispatcher
        .dispatch(&ctx, &grant, request, temp.path())
        .await;

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    let attempted = events
        .iter()
        .find(|e| e.event_type == "ToolInvocationAttempted")
        .unwrap();
    let key_val = attempted.payload.get("idempotency_key").unwrap();
    assert_eq!(key_val.as_str().unwrap(), "op-abc-123");
}

// ── schema export ─────────────────────────────────────────────────────────────

#[test]
fn schema_export_covers_all_four_tool_families() {
    let schemas = UnifiedToolRegistry::export_schemas();
    let tool_ids: Vec<&str> = schemas.iter().map(|s| s.tool_id.as_str()).collect();
    assert!(tool_ids.contains(&"filesystem"));
    assert!(tool_ids.contains(&"process"));
    assert!(tool_ids.contains(&"git"));
    assert!(tool_ids.contains(&"container"));
}

#[test]
fn schema_export_contains_no_grant_or_secret_fields() {
    let schemas = UnifiedToolRegistry::export_schemas();
    let serialized = serde_json::to_string(&schemas).unwrap();
    assert!(!serialized.contains("grant_id"));
    assert!(!serialized.contains("expires_at"));
    assert!(!serialized.contains("revoked"));
    assert!(!serialized.contains("capabilities"));
}

#[test]
fn schema_export_required_fields_are_present() {
    let schemas = UnifiedToolRegistry::export_schemas();
    for schema in &schemas {
        assert!(!schema.tool_id.is_empty());
        assert!(!schema.operation_id.is_empty());
        assert!(!schema.description.is_empty());
        assert!(!schema.required_capability.is_empty());
    }
}

#[test]
fn schema_export_is_valid_json() {
    let schemas = UnifiedToolRegistry::export_schemas();
    let json = serde_json::to_string_pretty(&schemas).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(reparsed.is_array());
}
