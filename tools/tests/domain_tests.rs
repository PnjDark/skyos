use kernel::artifacts::registry::ArtifactRegistry;
use kernel::domain::schemas::{
    AcademySchema, FinanceSchema, FitnessSchema, PantrySchema, ProductivitySchema,
};
use kernel::domain::DomainStore;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use kernel::persistence::db::DatabaseConnectionPool;
use serde_json::json;
use tempfile::{tempdir, TempDir};
use tools::domain::{EVENT_DOMAIN_COMPLETED, EVENT_DOMAIN_FAILED};
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolStatus};
use uuid::Uuid;

// ── Test harness ─────────────────────────────────────────────────────────────

fn setup_test_env() -> (
    TempDir,
    EventBus,
    ArtifactRegistry,
    GrantIssuer,
    DomainStore,
) {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("runtime.db");
    let pool = DatabaseConnectionPool::open(&db_path).unwrap();
    let event_bus = EventBus::open(&db_path).unwrap();
    let artifact_registry = ArtifactRegistry::open(&db_path, temp.path().join("cas")).unwrap();
    let grant_issuer = GrantIssuer::new();
    let domain_store = DomainStore::open(pool);

    // Register all 5 core domain schemas
    domain_store.register_domain(&FitnessSchema).unwrap();
    domain_store.register_domain(&PantrySchema).unwrap();
    domain_store.register_domain(&FinanceSchema).unwrap();
    domain_store.register_domain(&AcademySchema).unwrap();
    domain_store.register_domain(&ProductivitySchema).unwrap();

    (
        temp,
        event_bus,
        artifact_registry,
        grant_issuer,
        domain_store,
    )
}

fn domain_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    namespace: &str,
    read_only: bool,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::DomainAccess {
            namespace: namespace.to_string(),
            read_only,
        }],
        None,
    )
}

// ── Schema registration & table existence ───────────────────────────────────

#[test]
fn domain_registration_creates_all_tables_idempotently() {
    let (_temp, _bus, _reg, _issuer, store) = setup_test_env();

    // Re-registering must succeed (idempotent CREATE TABLE IF NOT EXISTS)
    assert!(store.register_domain(&FitnessSchema).is_ok());
    assert!(store.register_domain(&PantrySchema).is_ok());
    assert!(store.register_domain(&FinanceSchema).is_ok());
    assert!(store.register_domain(&AcademySchema).is_ok());
    assert!(store.register_domain(&ProductivitySchema).is_ok());
}

// ── Fitness domain ──────────────────────────────────────────────────────────

#[tokio::test]
async fn fitness_mutate_and_query_flow() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // 1. Insert workout
    let mutate_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "INSERT INTO fitness__workouts (workout_id, task_id, performed_at, notes) VALUES (?, ?, ?, ?)",
            "params": ["w1", task_id.to_string(), "2026-10-21T10:00:00Z", "Leg day progressive overload"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);

    // 2. Insert set
    let mutate_set_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "INSERT INTO fitness__sets (set_id, workout_id, exercise, weight_kg, reps, rpe, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            "params": ["s1", "w1", "Barbell Squat", 140.0, 5, 8.5, "2026-10-21T10:05:00Z"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_set_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);

    // 3. Query sets
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT exercise, weight_kg, reps, rpe FROM fitness__sets WHERE workout_id = ?",
            "params": ["w1"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);
    let output_str = match res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["exercise"], "Barbell Squat");
    assert_eq!(rows[0]["weight_kg"], 140.0);
    assert_eq!(rows[0]["reps"], 5);
}

// ── Pantry domain ───────────────────────────────────────────────────────────

#[tokio::test]
async fn pantry_mutate_and_query_flow() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "pantry", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Insert item: Plantains
    let mutate_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "pantry",
            "sql": "INSERT INTO pantry__items (item_id, name, category, unit, quantity, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            "params": ["p1", "Plantains", "Produce", "kg", 15.0, "2026-10-21T08:00:00Z"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);

    // Insert price at local Douala market
    let price_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "pantry",
            "sql": "INSERT INTO pantry__prices (price_id, item_id, market, price_xaf, recorded_at) VALUES (?, ?, ?, ?, ?)",
            "params": ["pr1", "p1", "Marché Sandaga", 5000.0, "2026-10-21T08:30:00Z"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, price_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);

    // Query item with price
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "pantry",
            "sql": "SELECT i.name, i.quantity, p.market, p.price_xaf FROM pantry__items i JOIN pantry__prices p ON i.item_id = p.item_id WHERE i.name = ?",
            "params": ["Plantains"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);
    let output_str = match res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Plantains");
    assert_eq!(rows[0]["price_xaf"], 5000.0);
}

// ── Finance domain ──────────────────────────────────────────────────────────

#[tokio::test]
async fn finance_multi_rail_ledger_flow() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "finance", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Record UBA Visa transaction
    let visa_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "finance",
            "sql": "INSERT INTO finance__ledger (entry_id, task_id, amount, currency, rail, direction, description, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            "params": ["f1", task_id.to_string(), 45000.0, "XAF", "UBA_VISA", "debit", "Server hosting renewal", "2026-10-21T09:00:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, visa_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Record MoMo transaction
    let momo_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "finance",
            "sql": "INSERT INTO finance__ledger (entry_id, task_id, amount, currency, rail, direction, description, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            "params": ["f2", task_id.to_string(), 12500.0, "XAF", "MTN_MOMO", "debit", "Pantry restock", "2026-10-21T10:00:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, momo_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Query ledger sum
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "finance",
            "sql": "SELECT SUM(amount) AS total_spent FROM finance__ledger WHERE direction = 'debit'",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);
    let output_str = match res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows[0]["total_spent"], 57500.0);
}

// ── Academy domain ──────────────────────────────────────────────────────────

#[tokio::test]
async fn academy_socratic_session_flow() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "academy", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Create session
    let session_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "academy",
            "sql": "INSERT INTO academy__sessions (session_id, task_id, topic, started_at) VALUES (?, ?, ?, ?)",
            "params": ["ac1", task_id.to_string(), "Distributed Consensus Protocols", "2026-10-21T11:00:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, session_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Record exchange with evaluation score
    let exchange_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "academy",
            "sql": "INSERT INTO academy__exchanges (exchange_id, session_id, role, content, score, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            "params": ["ex1", "ac1", "evaluation", "Clear explanation of Byzantine Fault Tolerance under network partitions.", 9.5, "2026-10-21T11:15:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, exchange_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Query exchanges
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "academy",
            "sql": "SELECT role, score, content FROM academy__exchanges WHERE session_id = ?",
            "params": ["ac1"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);
    let output_str = match res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["score"], 9.5);
}

// ── Productivity domain ─────────────────────────────────────────────────────

#[tokio::test]
async fn productivity_items_and_vault_flow() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "productivity", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Insert task item
    let item_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "productivity",
            "sql": "INSERT INTO productivity__items (item_id, kind, title, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            "params": ["it1", "task", "Implement Domain Memory", "in_progress", "2026-10-21T07:00:00Z", "2026-10-21T07:00:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, item_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Insert knowledge vault note linked to the item
    let vault_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "productivity",
            "sql": "INSERT INTO productivity__vault_entries (entry_id, item_id, content, tags, created_at) VALUES (?, ?, ?, ?, ?)",
            "params": ["ve1", "it1", "Domain memory architecture maps namespaces into isolated table prefixes in SQLite WAL.", "architecture,kernel", "2026-10-21T07:30:00Z"]
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &grant, vault_req, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // Query items
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "productivity",
            "sql": "SELECT i.title, v.content FROM productivity__items i JOIN productivity__vault_entries v ON i.item_id = v.item_id WHERE i.kind = ?",
            "params": ["task"]
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);
}

// ── Policy & Boundary Enforcement Tests ─────────────────────────────────────

#[tokio::test]
async fn policy_read_only_grant_rejects_mutate() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    // Grant is read_only = true
    let grant = domain_grant(&issuer, task_id, "fitness", true);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let mutate_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "INSERT INTO fitness__workouts (workout_id, task_id, performed_at) VALUES ('w2', 't', '2026-10-21')",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("Policy Engine denied"));

    // But query is permitted
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT COUNT(*) FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let query_res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(query_res.status, ToolStatus::Succeeded);
}

#[tokio::test]
async fn policy_different_namespace_grant_denied() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    // Grant is for pantry only
    let grant = domain_grant(&issuer, task_id, "pantry", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT COUNT(*) FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("Policy Engine denied"));
}

#[tokio::test]
async fn policy_expired_and_revoked_grant_denied() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut grant = domain_grant(&issuer, task_id, "finance", false);
    grant.revoked = true;

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "finance",
            "sql": "SELECT * FROM finance__ledger",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("Policy Engine denied"));
}

#[tokio::test]
async fn namespace_validation_rejects_malformed_string() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness; DROP TABLE", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness; DROP TABLE",
            "sql": "SELECT * FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("invalid characters"));
}

#[tokio::test]
async fn query_rejects_non_select_sql() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "DELETE FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res
        .error_message
        .unwrap()
        .contains("Only SELECT statements are permitted"));
}

#[tokio::test]
async fn mutate_rejects_select_sql() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    let mutate_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT * FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res
        .error_message
        .unwrap()
        .contains("SELECT is not permitted in mutate"));
}

#[tokio::test]
async fn dispatcher_without_domain_store_fails_gracefully() {
    let (temp, bus, mut reg, issuer, _store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    // Dispatcher initialized WITHOUT .with_domain_store()
    let mut dispatcher = UnifiedToolRegistry::new(&bus, &mut reg, &issuer);

    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT * FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, query_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res
        .error_message
        .unwrap()
        .contains("Domain store not configured"));
}

#[tokio::test]
async fn audit_events_persisted_for_domain_operations() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Succeeded operation emits DomainOperationCompleted
    let mutate_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "INSERT INTO fitness__workouts (workout_id, task_id, performed_at) VALUES ('w_audit', 't', '2026-10-21')",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, mutate_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Succeeded);

    let events = bus.get_events_for_task(&task_id.to_string()).unwrap();
    let completed_event = events
        .iter()
        .find(|e| e.event_type == EVENT_DOMAIN_COMPLETED);
    assert!(completed_event.is_some());

    // Failed operation emits DomainOperationFailed
    let bad_query = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT non_existent_column FROM fitness__workouts",
            "params": []
        }),
        idempotency_key: None,
    };
    let bad_res = dispatcher
        .dispatch(&ctx, &grant, bad_query, temp.path())
        .await;
    assert_eq!(bad_res.status, ToolStatus::Failed);

    let events = bus.get_events_for_task(&task_id.to_string()).unwrap();
    let failed_event = events.iter().find(|e| e.event_type == EVENT_DOMAIN_FAILED);
    assert!(failed_event.is_some());
}

// ── Adversarial Security & Isolation Gate ───────────────────────────────────

#[tokio::test]
async fn cross_namespace_mutate_attack_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    // Adversary is legitimately granted write capability to "fitness"
    let grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // First populate pantry under a legitimate pantry grant
    let pantry_grant = domain_grant(&issuer, task_id, "pantry", false);
    let init_pantry = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "pantry",
            "sql": "INSERT INTO pantry__items (item_id, name, category, unit, quantity, updated_at) VALUES ('p_sec', 'Cassava', 'Produce', 'kg', 10, '2026-10-21')",
            "params": []
        }),
        idempotency_key: None,
    };
    assert_eq!(
        dispatcher
            .dispatch(&ctx, &pantry_grant, init_pantry, temp.path())
            .await
            .status,
        ToolStatus::Succeeded
    );

    // ATTACK: Adversary attempts to DELETE from pantry__items using fitness grant and namespace="fitness"
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "DELETE FROM pantry__items WHERE item_id = 'p_sec'",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("not authorized"));

    // Verify pantry item was NOT deleted
    let verify_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "pantry",
            "sql": "SELECT COUNT(*) AS c FROM pantry__items WHERE item_id = 'p_sec'",
            "params": []
        }),
        idempotency_key: None,
    };
    let verify_res = dispatcher
        .dispatch(&ctx, &pantry_grant, verify_req, temp.path())
        .await;
    assert_eq!(verify_res.status, ToolStatus::Succeeded);
    let output_str = match verify_res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows[0]["c"], 1);
}

#[tokio::test]
async fn cross_namespace_read_attack_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    // Legitimate read grant to fitness only
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", true);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // ATTACK: Try to read finance__ledger while passing namespace="fitness"
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT * FROM finance__ledger",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    let err = res.error_message.unwrap();
    assert!(err.contains("prohibited") || err.contains("not authorized"));
}

#[tokio::test]
async fn cross_namespace_join_attack_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", true);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // ATTACK: Sneak a read to academy__sessions via JOIN
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT f.workout_id, a.topic FROM fitness__workouts f JOIN academy__sessions a ON 1=1",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    let err = res.error_message.unwrap();
    assert!(err.contains("prohibited") || err.contains("not authorized"));
}

#[tokio::test]
async fn cte_write_attack_in_query_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", true);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // ATTACK: Use CTE to smuggle a DELETE through a SELECT query
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "WITH deleted AS (DELETE FROM fitness__workouts RETURNING *) SELECT * FROM deleted",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
}

#[tokio::test]
async fn system_table_inspection_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", true);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // ATTACK: Try to inspect schema metadata via sqlite_master
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT name FROM sqlite_master WHERE type = 'table'",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    let err = res.error_message.unwrap();
    assert!(err.contains("prohibited") || err.contains("not authorized"));
}

#[tokio::test]
async fn pragma_execution_blocked_by_authorizer() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "adversary");
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // ATTACK: Execute PRAGMA
    let attack_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "PRAGMA journal_mode = DELETE",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, attack_req, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);
    assert!(res.error_message.unwrap().contains("not authorized"));
}

#[tokio::test]
async fn transaction_rollback_on_constraint_violation() {
    let (temp, bus, mut reg, issuer, store) = setup_test_env();
    let task_id = Uuid::new_v4();
    let ctx = ToolContext::new(task_id, "test_agent");
    let fitness_grant = domain_grant(&issuer, task_id, "fitness", false);

    let mut dispatcher =
        UnifiedToolRegistry::new(&bus, &mut reg, &issuer).with_domain_store(&store);

    // Attempt to insert a set referencing a non-existent workout (FOREIGN KEY constraint violation)
    let bad_set = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "mutate".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "INSERT INTO fitness__sets (set_id, workout_id, exercise, weight_kg, reps, created_at) VALUES ('bad_s', 'non_existent_w', 'Deadlift', 200, 3, '2026-10-21')",
            "params": []
        }),
        idempotency_key: None,
    };
    let res = dispatcher
        .dispatch(&ctx, &fitness_grant, bad_set, temp.path())
        .await;
    assert_eq!(res.status, ToolStatus::Failed);

    // Verify nothing exists in fitness__sets
    let query_req = InvocationRequest {
        tool_id: "domain".into(),
        operation_id: "query".into(),
        parameters: json!({
            "namespace": "fitness",
            "sql": "SELECT COUNT(*) AS total FROM fitness__sets",
            "params": []
        }),
        idempotency_key: None,
    };
    let q_res = dispatcher
        .dispatch(&ctx, &fitness_grant, query_req, temp.path())
        .await;
    assert_eq!(q_res.status, ToolStatus::Succeeded);
    let output_str = match q_res.output {
        tools::types::ToolOutput::Text(t) => t,
        _ => panic!("Expected text output"),
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output_str).unwrap();
    assert_eq!(rows[0]["total"], 0);
}
