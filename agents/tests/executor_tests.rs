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
use std::process::Command;
use std::sync::Arc;

use agents::executor::{ExecutorAgent, ExecutorServices};
use agents::types::{AgentBudget, AgentLoopStatus};
use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::identity::{
    ActorAuthenticator, ActorClaim, ActorKind, AuthError, AuthMethod, VerifiedIdentity,
};
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::{AuthorizationPolicy, policy_for_agent};
use kernel::permissions::types::{Capability, CapabilityKind};
use kernel::persistence::db::DatabaseConnectionPool;
use kernel::recovery::{
    AuthorizationContext, AuthorizationStore, ReconciliationStore, RecoveryEngine,
    RecoveryServices, RetryPermit,
};
use kernel::tasks::checkpoint::{
    CheckpointInvocation, CheckpointStatus, CheckpointStore, SideEffectSemantics,
    compute_argument_fingerprint, compute_idempotency_key,
};
use kernel::tasks::{state::TaskState, store::TaskStore};
use models::provider::{ActionProposal, ScriptedModelProvider};
use uuid::Uuid;

// ── Test harness helpers ──────────────────────────────────────────────────────

/// The executor tests never reconcile; this authenticator exists only so the
/// engine can be constructed with a real trust boundary.
struct TestAuthenticator;

impl ActorAuthenticator for TestAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        if claim.kind == ActorKind::Agent {
            return Err(AuthError::UnsupportedActorKind {
                kind: ActorKind::Agent,
                reason: "tests never authenticate an agent".into(),
            });
        }
        Ok(VerifiedIdentity::new(
            "test-agent",
            ActorKind::Operator,
            AuthMethod::HarnessOnly,
        ))
    }
}

struct TestRig {
    #[allow(dead_code)] // kept for RAII – TempDir deletes the directory on drop
    db_dir: tempfile::TempDir,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
    checkpoint_store: CheckpointStore,
    authorization_store: AuthorizationStore,
    reconciliation_store: ReconciliationStore,
    policy: Arc<AuthorizationPolicy>,
    artifact_registry: ArtifactRegistry,
    workspace_root: PathBuf,
}

fn git_commit_proposal() -> anyhow::Result<ActionProposal> {
    Ok(ActionProposal {
        tool_id: "git".into(),
        operation_id: "commit".into(),
        parameters: serde_json::json!({ "message": "test: commit before audit failure" }),
        is_complete: false,
    })
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
        let checkpoint_store = CheckpointStore::open(&db_path).unwrap();
        let authorization_store = AuthorizationStore::open(&db_path).unwrap();
        let reconciliation_store = ReconciliationStore::open(&db_path).unwrap();
        let artifact_registry =
            ArtifactRegistry::open(db_dir.path().join("artifacts.db"), artifact_store).unwrap();

        let rules = [
            Capability::FileSystemRead {
                root: workspace_root.clone(),
            },
            Capability::FileSystemWrite {
                root: workspace_root.clone(),
            },
            Capability::GitRead {
                repo_root: workspace_root.clone(),
            },
            Capability::GitWrite {
                repo_root: workspace_root.clone(),
            },
        ];

        Self {
            db_dir,
            task_store,
            event_bus,
            grant_issuer,
            checkpoint_store,
            authorization_store,
            reconciliation_store,
            policy: Arc::new(policy_for_agent(
                "executor-test-policy",
                1,
                "test-agent",
                rules,
            )),
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

    /// The policy in force for every test agent.  It permits exactly the
    /// capability families these tests exercise, rooted at the rig workspace.
    fn build_agent(&self, model: Arc<ScriptedModelProvider>, budget: AgentBudget) -> ExecutorAgent {
        self.build_agent_with_permit(model, budget, None)
    }

    fn build_agent_with_permit(
        &self,
        model: Arc<ScriptedModelProvider>,
        budget: AgentBudget,
        resume_permit: Option<RetryPermit>,
    ) -> ExecutorAgent {
        ExecutorAgent::new(
            "test-agent",
            ExecutorServices {
                task_store: self.task_store.clone(),
                grant_issuer: self.grant_issuer.clone(),
                event_bus: self.event_bus.clone(),
                checkpoint_store: self.checkpoint_store.clone(),
                policy: self.policy.clone(),
                resume_permit,
            },
            model,
            &self.workspace_root,
            budget,
        )
    }

    fn recovery_engine(&self) -> RecoveryEngine {
        RecoveryEngine::new(RecoveryServices {
            checkpoint_store: self.checkpoint_store.clone(),
            task_store: self.task_store.clone(),
            event_bus: self.event_bus.clone(),
            grant_issuer: self.grant_issuer.clone(),
            authorization_store: self.authorization_store.clone(),
            reconciliation_store: self.reconciliation_store.clone(),
            policy: self.policy.clone(),
            authenticator: Arc::new(TestAuthenticator),
            probes: tools::reconciler::default_probes(),
        })
    }

    /// Reproduce a crash between "Pending persisted" and "Dispatched persisted"
    /// for a `filesystem.write_file` step, then let recovery classify it.
    fn seed_interrupted_write(&self, task_id: Uuid, arguments: serde_json::Value) -> SeededStep {
        let invocation_id = Uuid::new_v4();
        let key = compute_idempotency_key(&task_id, 0, "filesystem", "write_file", &arguments);
        let fingerprint = compute_argument_fingerprint(&arguments);

        let conn = self.checkpoint_store.connection().unwrap();
        CheckpointStore::write_pending_invocation(
            &conn,
            task_id,
            "test-agent",
            0,
            &CheckpointInvocation {
                invocation_id,
                idempotency_key: key.clone(),
                argument_fingerprint: fingerprint.clone(),
                semantics: SideEffectSemantics::AtMostOnce,
                tool_id: "filesystem".into(),
                operation_id: "write_file".into(),
            },
        )
        .unwrap();
        AuthorizationStore::record_with_connection(
            &conn,
            &AuthorizationContext {
                task_id,
                step_number: 0,
                agent_id: "test-agent".into(),
                capabilities: vec![Capability::FileSystemWrite {
                    root: self.workspace_root.clone(),
                }],
                required_capability: Some(CapabilityKind::FileSystemWrite),
                policy_id: self.policy.policy_id().to_string(),
                policy_version: self.policy.version(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
        drop(conn);

        self.recovery_engine().recover_all().unwrap();

        SeededStep {
            invocation_id,
            idempotency_key: key,
            argument_fingerprint: fingerprint,
        }
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

    let checkpoint = rig
        .checkpoint_store
        .latest_for_task(task_id)
        .unwrap()
        .expect("tool invocation checkpoint should be persisted");
    assert_eq!(checkpoint.status, CheckpointStatus::Succeeded);
    assert_eq!(checkpoint.agent_id, "test-agent");
    assert_eq!(checkpoint.tool_id.as_deref(), Some("filesystem"));
    assert_eq!(checkpoint.operation_id.as_deref(), Some("read_file"));
    assert_eq!(
        checkpoint.invocation_id,
        Some(summary.step_records[0].correlation_id),
        "the invocation ID must be stable from checkpoint through the result"
    );
    assert!(checkpoint.idempotency_key.is_some());
    let events = rig
        .event_bus
        .get_events_for_task(&task_id.to_string())
        .unwrap();
    assert!(events.iter().any(|event| {
        event.event_type == "AgentStepCompleted"
            && event.payload.get("correlation_id")
                == Some(&serde_json::json!(summary.step_records[0].correlation_id))
    }));
}

#[tokio::test]
async fn git_commit_audit_failure_is_checkpointed_as_unknown_without_repair() {
    let mut rig = TestRig::new();
    let task_id = rig
        .task_store
        .create_task("Commit audit recovery test", TaskState::Ready, 1)
        .unwrap();
    rig.grant_issuer.issue_grant(
        "test-agent",
        task_id,
        vec![
            Capability::GitRead {
                repo_root: rig.workspace_root.clone(),
            },
            Capability::GitWrite {
                repo_root: rig.workspace_root.clone(),
            },
        ],
        None,
    );

    let run_git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&rig.workspace_root)
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
    std::fs::write(rig.workspace_root.join("tracked.txt"), "commit me").unwrap();
    run_git(&["add", "--", "tracked.txt"]);

    DatabaseConnectionPool::open(rig.db_dir.path().join("runtime_state.db"))
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

    let model = Arc::new(ScriptedModelProvider::new(vec![
        git_commit_proposal(),
        complete_proposal(),
    ]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert!(matches!(
        summary.status,
        AgentLoopStatus::OutcomeUnknown { .. }
    ));
    assert_eq!(
        summary.steps_executed, 1,
        "the uncertain commit must stop the loop rather than trigger a repair retry"
    );
    assert_eq!(
        rig.checkpoint_store
            .latest_for_task(task_id)
            .unwrap()
            .unwrap()
            .status,
        CheckpointStatus::OutcomeUnknown
    );
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(&rig.workspace_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the physical commit must exist despite the failed completion audit"
    );
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

// ── Phase 5.2: recovery authorization gates task resumption ──────────────────

#[derive(Debug, Clone)]
struct SeededStep {
    invocation_id: Uuid,
    idempotency_key: String,
    argument_fingerprint: String,
}

fn write_file_proposal(content: &str) -> anyhow::Result<ActionProposal> {
    Ok(ActionProposal {
        tool_id: "filesystem".into(),
        operation_id: "write_file".into(),
        parameters: serde_json::json!({
            "relative_path": "resume.txt",
            "content": content,
        }),
        is_complete: false,
    })
}

#[tokio::test]
async fn retry_ready_checkpoint_blocks_implicit_resumption() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();
    let arguments = serde_json::json!({ "relative_path": "resume.txt", "content": "v1" });
    rig.seed_interrupted_write(task_id, arguments);

    let model = Arc::new(ScriptedModelProvider::new(vec![
        write_file_proposal("v1"),
        complete_proposal(),
    ]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert!(
        matches!(summary.status, AgentLoopStatus::ResumeRejected { .. }),
        "expected ResumeRejected, got {:?}",
        summary.status
    );
    assert!(
        !rig.workspace_root.join("resume.txt").exists(),
        "nothing may be dispatched without a recovery authorization"
    );
    assert_eq!(
        rig.checkpoint_store
            .latest_for_task(task_id)
            .unwrap()
            .unwrap()
            .status,
        CheckpointStatus::RetryReady
    );
}

#[tokio::test]
async fn outcome_unknown_checkpoint_blocks_the_task_until_reconciled() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();
    let arguments = serde_json::json!({ "relative_path": "resume.txt", "content": "v1" });
    let seeded = rig.seed_interrupted_write(task_id, arguments);

    // The process died after dispatch: the ledger can no longer prove anything
    // about the external world.
    let conn = rig.checkpoint_store.connection().unwrap();
    CheckpointStore::mark_dispatched(
        &conn,
        task_id,
        0,
        seeded.invocation_id,
        &seeded.idempotency_key,
        "filesystem",
        "write_file",
    )
    .unwrap();
    drop(conn);
    rig.recovery_engine().recover_all().unwrap();

    let model = Arc::new(ScriptedModelProvider::new(vec![
        write_file_proposal("v1"),
        complete_proposal(),
    ]));
    let agent = rig.build_agent(model, AgentBudget::default());
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    match summary.status {
        AgentLoopStatus::ResumeRejected { reason } => {
            assert!(
                reason.contains("unknown external outcome"),
                "unexpected rejection reason: {reason}"
            );
        }
        other => panic!("expected ResumeRejected, got {other:?}"),
    }
    assert!(!rig.workspace_root.join("resume.txt").exists());
}

#[tokio::test]
async fn authorized_retry_redispatches_the_recorded_invocation() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();
    let arguments = serde_json::json!({ "relative_path": "resume.txt", "content": "v1" });
    let seeded = rig.seed_interrupted_write(task_id, arguments);

    let permit = rig
        .recovery_engine()
        .prepare_retry(task_id, 0, "test-agent")
        .expect("policy still permits the recorded capability intent");
    assert_eq!(permit.invocation_id, seeded.invocation_id);
    assert_eq!(permit.argument_fingerprint, seeded.argument_fingerprint);
    let retry_grant_id = permit.grant.grant_id;

    let model = Arc::new(ScriptedModelProvider::new(vec![
        write_file_proposal("v1"),
        complete_proposal(),
    ]));
    let agent = rig.build_agent_with_permit(model, AgentBudget::default(), Some(permit));
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert_eq!(summary.status, AgentLoopStatus::Completed);
    assert_eq!(
        std::fs::read_to_string(rig.workspace_root.join("resume.txt")).unwrap(),
        "v1"
    );

    let checkpoints = rig.checkpoint_store.list_for_task(task_id).unwrap();
    assert_eq!(
        checkpoints.len(),
        1,
        "a resumed retry must complete the existing step, never add a new one"
    );
    assert_eq!(checkpoints[0].status, CheckpointStatus::Succeeded);
    assert_eq!(
        checkpoints[0].invocation_id,
        Some(seeded.invocation_id),
        "the retry must reuse the invocation identity recorded before the crash"
    );
    assert_eq!(
        checkpoints[0].idempotency_key.as_deref(),
        Some(seeded.idempotency_key.as_str())
    );

    let events = rig
        .event_bus
        .get_events_for_task(&task_id.to_string())
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "ToolInvocationReDispatched"),
        "the re-dispatch must be auditable"
    );

    assert!(
        rig.grant_issuer
            .get_grant(&retry_grant_id)
            .map(|grant| grant.revoked)
            .unwrap_or(false),
        "the recovery grant must not outlive the retry it authorized"
    );
}

#[tokio::test]
async fn resume_with_diverging_arguments_is_rejected_without_side_effects() {
    let mut rig = TestRig::new();
    let task_id = rig.setup_task_with_grant();
    let arguments = serde_json::json!({ "relative_path": "resume.txt", "content": "v1" });
    rig.seed_interrupted_write(task_id, arguments);

    let permit = rig
        .recovery_engine()
        .prepare_retry(task_id, 0, "test-agent")
        .unwrap();

    // The model now wants different content.  That is a new intent, not a
    // replay, and it may not overwrite the unresolved recorded attempt.
    let model = Arc::new(ScriptedModelProvider::new(vec![
        write_file_proposal("v2"),
        complete_proposal(),
    ]));
    let agent = rig.build_agent_with_permit(model, AgentBudget::default(), Some(permit));
    let summary = agent.run(task_id, &mut rig.artifact_registry).await;

    assert!(
        matches!(summary.status, AgentLoopStatus::ResumeRejected { .. }),
        "expected ResumeRejected, got {:?}",
        summary.status
    );
    assert!(
        !rig.workspace_root.join("resume.txt").exists(),
        "a diverging proposal must not be executed under the old authorization"
    );
    assert_eq!(
        rig.checkpoint_store
            .latest_for_task(task_id)
            .unwrap()
            .unwrap()
            .status,
        CheckpointStatus::RetryReady
    );
}
