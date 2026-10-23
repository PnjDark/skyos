/// Adversarial integration tests for `ExecutorAgent`.
///
/// Each test wires real kernel components (TaskStore, GrantIssuer, EventBus,
/// ArtifactRegistry) against a `ScriptedModelProvider` so that the execution
/// contract is verified without a live LLM.
///
/// Coverage targets
/// ────────────────
/// 1. Happy path – model completes in one cycle.
/// 2. Budget: step count exhaustion.
/// 3. Budget: repair count exhaustion on repeated tool failures.
/// 4. Permission denial – loop fails closed immediately.
/// 5. Grant expires mid-loop – loop fails closed before next dispatch.
/// 6. Model signals `is_complete = true` – loop stops immediately.
use std::path::PathBuf;
use std::sync::Arc;

use agents::executor::ExecutorAgent;
use agents::types::{AgentBudget, AgentLoopStatus};
use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use kernel::tasks::{state::TaskState, store::TaskStore};
use models::provider::{ActionProposal, ScriptedModelProvider};
use uuid::Uuid;

// ── Test harness helpers ──────────────────────────────────────────────────────

struct TestRig {
    #[allow(dead_code)] // kept for RAII – TempDir deletes the directory on drop
    db_dir: tempfile::TempDir,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
    artifact_registry: ArtifactRegistry,
    workspace_root: PathBuf,
}

impl TestRig {
    fn new() -> Self {
        let db_dir = tempfile::tempdir().expect("tempdir");
        let db_path = db_dir.path().join("runtime_state.db");
        let artifact_store = db_dir.path().join("artifacts");
        let workspace_root = db_dir.path().join("workspace");
        std::fs::create_dir_all(&workspace_root).unwrap();

        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        let grant_issuer = GrantIssuer::new();
        let artifact_registry =
            ArtifactRegistry::open(db_dir.path().join("artifacts.db"), artifact_store).unwrap();

        Self {
            db_dir,
            task_store,
            event_bus,
            grant_issuer,
            artifact_registry,
            workspace_root,
        }
    }

    /// Create a task and issue a 15-minute capability grant for it.
    fn setup_task_with_grant(&self) -> Uuid {
        let task_id = self
            .task_store
            .create_task("Test task", TaskState::Ready, 1)
            .unwrap();

        self.grant_issuer.issue_grant(
            "test-agent",
            task_id,
            vec![Capability::FileSystemRead {
                root: self.workspace_root.clone(),
            }],
            None, // 15 minute default TTL
        );

        task_id
    }

    /// Create a task WITHOUT issuing a grant.
    fn setup_task_no_grant(&self) -> Uuid {
        self.task_store
            .create_task("No-grant task", TaskState::Ready, 1)
            .unwrap()
    }

    fn build_agent(&self, model: Arc<ScriptedModelProvider>, budget: AgentBudget) -> ExecutorAgent {
        ExecutorAgent::new(
            "test-agent",
            self.task_store.clone(),
            self.grant_issuer.clone(),
            self.event_bus.clone(),
            model,
            &self.workspace_root,
            budget,
        )
    }
}

/// Scripted action that completes immediately (no tool call).
fn complete_proposal() -> anyhow::Result<ActionProposal> {
    Ok(ActionProposal {
        tool_id: "__complete__".into(),
        operation_id: "__complete__".into(),
        parameters: serde_json::Value::Null,
        is_complete: true,
    })
}

/// Scripted action that invokes a filesystem read (should succeed if grant allows it).
fn fs_read_proposal(path: &str) -> anyhow::Result<ActionProposal> {
    Ok(ActionProposal {
        tool_id: "filesystem".into(),
        operation_id: "read_file".into(),
        parameters: serde_json::json!({ "relative_path": path }),
        is_complete: false,
    })
}

/// Scripted action that invokes an unknown tool (will produce ToolFailed).
fn bad_tool_proposal() -> anyhow::Result<ActionProposal> {
    Ok(ActionProposal {
        tool_id: "nonexistent_tool".into(),
        operation_id: "do_thing".into(),
        parameters: serde_json::Value::Null,
        is_complete: false,
    })
}

// ── Test 1: immediate completion ──────────────────────────────────────────────

#[tokio::test]
async fn test_immediate_completion() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();

    let model = Arc::new(ScriptedModelProvider::new(vec![complete_proposal()]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert_eq!(summary.status, AgentLoopStatus::Completed);
    assert_eq!(summary.steps_executed, 1);
    assert_eq!(summary.repair_attempts, 0);
}

// ── Test 2: step budget exhaustion ───────────────────────────────────────────

#[tokio::test]
async fn test_step_budget_exhaustion() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();

    // The model never signals completion; it always proposes a tool call.
    // With max_steps = 3 the loop must stop after 3 cycles.
    let responses: Vec<anyhow::Result<ActionProposal>> =
        (0..20).map(|_| fs_read_proposal("readme.txt")).collect();
    let model = Arc::new(ScriptedModelProvider::new(responses));

    let budget = AgentBudget {
        max_steps: 3,
        max_wall_seconds: 60,
        max_repair_attempts: 5,
    };
    let agent = rig.build_agent(model, budget);
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert!(
        matches!(summary.status, AgentLoopStatus::BudgetExhausted { .. }),
        "expected BudgetExhausted, got {:?}",
        summary.status
    );
}

// ── Test 3: repair budget exhaustion ─────────────────────────────────────────

#[tokio::test]
async fn test_repair_budget_exhaustion() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();

    // Every proposal targets a nonexistent tool so every step returns ToolFailed.
    let responses: Vec<anyhow::Result<ActionProposal>> =
        (0..20).map(|_| bad_tool_proposal()).collect();
    let model = Arc::new(ScriptedModelProvider::new(responses));

    let budget = AgentBudget {
        max_steps: 50,
        max_wall_seconds: 60,
        max_repair_attempts: 2, // very tight
    };
    let agent = rig.build_agent(model, budget);
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert!(
        matches!(summary.status, AgentLoopStatus::BudgetExhausted { .. }),
        "expected BudgetExhausted, got {:?}",
        summary.status
    );
    // Must have consumed at least max_repair_attempts + 1 cycles
    assert!(summary.repair_attempts > 2);
}

// ── Test 4: no grant → fail closed ───────────────────────────────────────────

#[tokio::test]
async fn test_no_grant_fails_closed() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_no_grant(); // deliberately no grant

    let model = Arc::new(ScriptedModelProvider::new(vec![fs_read_proposal(
        "readme.txt",
    )]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert_eq!(
        summary.status,
        AgentLoopStatus::PermissionDenied,
        "loop must fail closed when no grant exists"
    );
    assert_eq!(
        summary.steps_executed, 0,
        "no step should be recorded before the grant check"
    );
}

// ── Test 5: grant revoked mid-loop ────────────────────────────────────────────

#[tokio::test]
async fn test_revoked_grant_fails_closed() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();

    // Immediately revoke the grant so the first cycle fails.
    let grant = rig
        .grant_issuer
        .get_active_grant_for_task(&task_id)
        .expect("grant should exist");
    rig.grant_issuer.revoke_grant(&grant.grant_id).unwrap();

    let model = Arc::new(ScriptedModelProvider::new(vec![fs_read_proposal(
        "readme.txt",
    )]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert_eq!(
        summary.status,
        AgentLoopStatus::PermissionDenied,
        "revoked grant must cause fail-closed"
    );
}

// ── Test 6: model signals completion after one real step ──────────────────────

#[tokio::test]
async fn test_complete_after_real_step() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();

    // Create the file so filesystem read succeeds
    let readme = rig.workspace_root.join("readme.txt");
    std::fs::write(&readme, "hello sky").unwrap();

    let model = Arc::new(ScriptedModelProvider::new(vec![
        fs_read_proposal("readme.txt"),
        complete_proposal(),
    ]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert_eq!(summary.status, AgentLoopStatus::Completed);
    // 2 records: the tool step + the completion record
    assert_eq!(summary.steps_executed, 2);
}

// ── Test 7: task missing from store ──────────────────────────────────────────

#[tokio::test]
async fn test_missing_task_returns_internal_error() {
    let mut rig = TestRig::new();
    let phantom_task_id = Uuid::new_v4(); // never registered

    let model = Arc::new(ScriptedModelProvider::new(vec![]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(phantom_task_id, &mut rig.artifact_registry).await;

    assert!(
        matches!(summary.status, AgentLoopStatus::InternalError { .. }),
        "expected InternalError for missing task, got {:?}",
        summary.status
    );
}
