/// Phase 5 — Crash Recovery & Execution Semantics (kernel-level).
///
/// These tests pin the two invariants the Phase 5.1 audit required:
///
/// 1. **A checkpoint is not evidence about the external world.**
///    `Pending` proves the tool was never invoked; `Dispatched` proves only that
///    an attempt *may* have happened.  Every `Dispatched` row therefore becomes
///    `OutcomeUnknown` and blocks its task — including idempotent operations.
/// 2. **Retryability is not authorization.**
///    A `RetryReady` step can only be re-dispatched after `prepare_retry`
///    re-evaluates the recorded capability intent against the policy in force
///    and mints a fresh, narrowly scoped grant.
///
/// The companion `process_kill_tests` in the `crash_harness` crate prove the
/// same boundaries with real processes and real Git side effects; these tests
/// pin the decision logic itself.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kernel::events::EventBus;
use kernel::identity::{
    ActorAuthenticator, ActorClaim, ActorKind, AuthError, AuthMethod, VerifiedIdentity,
};
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::{AuthorizationPolicy, policy_for_agent};
use kernel::permissions::types::{Capability, CapabilityKind};
use kernel::recovery::{
    AuthorizationContext, AuthorizationError, AuthorizationStore, EvidenceKind, EvidenceProbe,
    EvidenceRef, EvidenceSpec, ProbeContext, ProbeError, ReconcileOutcome, ReconciliationAction,
    ReconciliationRequest, ReconciliationStore, RecoveryDecision, RecoveryEngine, RecoveryError,
    RecoveryServices,
};
use kernel::tasks::checkpoint::{
    CheckpointInvocation, CheckpointStatus, CheckpointStore, SideEffectSemantics,
    compute_argument_fingerprint, compute_idempotency_key,
};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use uuid::Uuid;

/// The baseline the rig records before dispatch, and the value every
/// reconciliation request must present.
const BASELINE: &str = "baseline-sha-0001";
const INTENT: &str = "recovery-test intent";

// ── Test harness ──────────────────────────────────────────────────────────────

/// Authenticates the rig's operator. `kind` is configurable so a test can
/// present an *agent* and prove the engine refuses it.
struct RigAuthenticator {
    kind: ActorKind,
}

impl ActorAuthenticator for RigAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        if claim.kind != self.kind {
            return Err(AuthError::UnsupportedActorKind {
                kind: claim.kind,
                reason: "rig authenticator is configured for a different actor kind".into(),
            });
        }
        Ok(VerifiedIdentity::new(
            "recovery-agent",
            self.kind,
            AuthMethod::HarnessOnly,
        ))
    }
}

/// Returns whatever observation the test staged. Defaults to an empty
/// observation, which the engine must resolve to `Indeterminate`.
struct ScriptedProbe {
    observation: Arc<Mutex<Option<serde_json::Value>>>,
}

impl EvidenceProbe for ScriptedProbe {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::GitCommit
    }

    fn probe(&self, _spec: &EvidenceSpec, _ctx: &ProbeContext) -> Result<EvidenceRef, ProbeError> {
        let staged = self
            .observation
            .lock()
            .expect("observation mutex")
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));

        Ok(EvidenceRef::new(
            EvidenceKind::GitCommit,
            "scripted probe",
            staged,
        ))
    }
}

struct RecoveryRig {
    _dir: tempfile::TempDir,
    workspace_root: PathBuf,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
    checkpoint_store: CheckpointStore,
    authorization_store: AuthorizationStore,
    reconciliation_store: ReconciliationStore,
    policy: Arc<AuthorizationPolicy>,
    observation: Arc<Mutex<Option<serde_json::Value>>>,
}

#[derive(Debug, Clone)]
struct SeededInvocation {
    invocation_id: Uuid,
    idempotency_key: String,
    argument_fingerprint: String,
}

impl RecoveryRig {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("runtime_state.db");
        let workspace_root = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace_root).unwrap();

        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        let grant_issuer = GrantIssuer::new();
        let checkpoint_store = CheckpointStore::open(&db_path).unwrap();
        let authorization_store = AuthorizationStore::open(&db_path).unwrap();
        let reconciliation_store = ReconciliationStore::open(&db_path).unwrap();
        let policy = Arc::new(Self::default_policy(&workspace_root));

        Self {
            _dir: dir,
            workspace_root,
            task_store,
            event_bus,
            grant_issuer,
            checkpoint_store,
            authorization_store,
            reconciliation_store,
            policy,
            observation: Arc::new(Mutex::new(None)),
        }
    }

    /// Stage what the scripted probe will observe on the next reconciliation.
    fn stage_observation(&self, observed: serde_json::Value) {
        *self.observation.lock().expect("observation mutex") = Some(observed);
    }

    /// The reconciliation authority for one task, held by the operator.
    fn reconciliation_grant(&self, task_id: Uuid) -> kernel::permissions::types::CapabilityGrant {
        self.grant_issuer.issue_grant(
            "recovery-agent",
            task_id,
            vec![Capability::SystemReconciliation { task_id }],
            None,
        )
    }

    /// Reconcile through the git-commit probe interface, using the rig's
    /// recorded baseline and staged observation.
    fn reconcile_git(
        &self,
        engine: &RecoveryEngine,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<ReconcileOutcome, RecoveryError> {
        self.reconcile_git_with_claim(
            engine,
            task_id,
            step_number,
            ActorClaim::process(ActorKind::Operator),
        )
    }

    /// As [`Self::reconcile_git`], but presenting a specific claim. Used to
    /// prove an *agent* claim is refused after successful authentication.
    fn reconcile_git_with_claim(
        &self,
        engine: &RecoveryEngine,
        task_id: Uuid,
        step_number: usize,
        claim: ActorClaim,
    ) -> Result<ReconcileOutcome, RecoveryError> {
        let grant = self.reconciliation_grant(task_id);
        let request = ReconciliationRequest::new(
            task_id,
            step_number,
            self.recorded_invocation(task_id, step_number),
            "rig reconciliation",
            EvidenceSpec::GitCommitAfterBaseline {
                repo_root: self.workspace_root.clone(),
                baseline_commit: BASELINE.to_string(),
                intent_message: INTENT.to_string(),
            },
        );
        engine.reconcile(&claim, &grant, &request)
    }

    fn requeue_task(
        &self,
        engine: &RecoveryEngine,
        task_id: Uuid,
        reason: &str,
    ) -> Result<(), RecoveryError> {
        let grant = self.reconciliation_grant(task_id);
        engine.requeue(
            &ActorClaim::process(ActorKind::Operator),
            &grant,
            task_id,
            reason,
        )
    }

    fn default_policy(workspace_root: &Path) -> AuthorizationPolicy {
        let root = workspace_root.to_path_buf();
        policy_for_agent(
            "recovery-test-policy",
            1,
            "recovery-agent",
            [
                Capability::FileSystemRead { root: root.clone() },
                Capability::FileSystemWrite { root: root.clone() },
                Capability::GitRead {
                    repo_root: root.clone(),
                },
                Capability::GitWrite { repo_root: root },
            ],
        )
    }

    fn make_running_task(&self) -> Uuid {
        let task_id = self
            .task_store
            .create_task("recovery-test", TaskState::Ready, 1)
            .unwrap();
        self.task_store
            .transition_state(task_id, TaskState::Ready, TaskState::Claimed)
            .unwrap();
        self.task_store
            .transition_state(task_id, TaskState::Claimed, TaskState::Running)
            .unwrap();
        task_id
    }

    /// The invocation id recorded for `(task, step)`.
    fn recorded_invocation(&self, task_id: Uuid, step_number: usize) -> Uuid {
        self.checkpoint_store
            .get(task_id, step_number)
            .unwrap()
            .expect("checkpoint exists")
            .invocation_id
            .expect("checkpoint records an invocation id")
    }

    fn issue_grant(&self, task_id: Uuid) -> Uuid {
        self.grant_issuer
            .issue_grant(
                "recovery-agent",
                task_id,
                vec![Capability::FileSystemWrite {
                    root: self.workspace_root.clone(),
                }],
                None,
            )
            .grant_id
    }

    fn build_engine(&self) -> RecoveryEngine {
        self.build_engine_with_policy(self.policy.clone())
    }

    fn build_engine_with_policy(&self, policy: Arc<AuthorizationPolicy>) -> RecoveryEngine {
        self.build_engine_as(policy, ActorKind::Operator)
    }

    /// Build an engine whose authenticator presents `kind`. Used to prove an
    /// agent actor cannot reconcile even when it holds a valid grant.
    fn build_engine_as(&self, policy: Arc<AuthorizationPolicy>, kind: ActorKind) -> RecoveryEngine {
        RecoveryEngine::new(RecoveryServices {
            checkpoint_store: self.checkpoint_store.clone(),
            task_store: self.task_store.clone(),
            event_bus: self.event_bus.clone(),
            grant_issuer: self.grant_issuer.clone(),
            authorization_store: self.authorization_store.clone(),
            reconciliation_store: self.reconciliation_store.clone(),
            policy,
            authenticator: Arc::new(RigAuthenticator { kind }),
            probes: vec![Arc::new(ScriptedProbe {
                observation: self.observation.clone(),
            })],
        })
    }

    /// Write a `Pending` checkpoint together with its authorization context —
    /// exactly what the executor does before dispatch.
    #[allow(clippy::too_many_arguments)] // a fixture that spells out the whole row
    fn seed_pending(
        &self,
        task_id: Uuid,
        step: usize,
        semantics: SideEffectSemantics,
        capabilities: Vec<Capability>,
        tool: &str,
        operation: &str,
        arguments: serde_json::Value,
    ) -> SeededInvocation {
        let invocation_id = Uuid::new_v4();
        let key = compute_idempotency_key(&task_id, step, tool, operation, &arguments);
        let fingerprint = compute_argument_fingerprint(&arguments);

        let conn = self.checkpoint_store.connection().unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        CheckpointStore::write_pending_invocation(
            &tx,
            task_id,
            "recovery-agent",
            step,
            &CheckpointInvocation {
                invocation_id,
                idempotency_key: key.clone(),
                argument_fingerprint: fingerprint.clone(),
                semantics,
                tool_id: tool.to_string(),
                operation_id: operation.to_string(),
            },
        )
        .unwrap();
        AuthorizationStore::record_with_connection(
            &tx,
            &AuthorizationContext {
                task_id,
                step_number: step,
                agent_id: "recovery-agent".into(),
                capabilities,
                // Derived from the tool manifest in production; spelled out for
                // the fixture so each test states the operation's authority.
                required_capability: match (tool, operation) {
                    ("filesystem", "write_file" | "read_file") => {
                        Some(CapabilityKind::FileSystemWrite)
                    }
                    ("git", "commit") => Some(CapabilityKind::GitWrite),
                    _ => None,
                },
                policy_id: self.policy.policy_id().to_string(),
                policy_version: self.policy.version(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
        tx.commit().unwrap();

        SeededInvocation {
            invocation_id,
            idempotency_key: key,
            argument_fingerprint: fingerprint,
        }
    }

    fn seed_default_pending(
        &self,
        task_id: Uuid,
        step: usize,
        semantics: SideEffectSemantics,
    ) -> SeededInvocation {
        self.seed_pending(
            task_id,
            step,
            semantics,
            vec![Capability::FileSystemWrite {
                root: self.workspace_root.clone(),
            }],
            "filesystem",
            "write_file",
            serde_json::json!({ "relative_path": "note.txt", "content": "hello" }),
        )
    }

    fn mark_dispatched(&self, task_id: Uuid, step: usize, seeded: &SeededInvocation) {
        let mut conn = self.checkpoint_store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        CheckpointStore::mark_dispatched(
            &tx,
            task_id,
            step,
            seeded.invocation_id,
            &seeded.idempotency_key,
            "filesystem",
            "write_file",
        )
        .unwrap();
        // Phase 6.0: the runtime records the pre-dispatch baseline in the same
        // transaction as the dispatch, so reconciliation is bounded by it.
        self.event_bus
            .emit_event_with_connection(
                &tx,
                Some(&task_id.to_string()),
                "ToolInvocationDispatched",
                serde_json::json!({
                    "step_number": step,
                    "invocation_id": seeded.invocation_id,
                    "baseline_head": BASELINE,
                }),
            )
            .unwrap();
        tx.commit().unwrap();
    }

    fn status(&self, task_id: Uuid) -> CheckpointStatus {
        self.checkpoint_store
            .latest_for_task(task_id)
            .unwrap()
            .unwrap()
            .status
    }

    fn task_state(&self, task_id: Uuid) -> TaskState {
        self.task_store.get_task(&task_id).unwrap().unwrap().state
    }
}

/// `prepare_retry` wraps authorization failures, so unwrap before matching.
fn expect_authorization_error(error: RecoveryError) -> AuthorizationError {
    match error {
        RecoveryError::Authorization(inner) => inner,
        other => panic!("expected an authorization error, got {other:?}"),
    }
}

// ── Classification: Pending proves no dispatch ───────────────────────────────

#[test]
fn pending_checkpoint_becomes_retry_ready() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);

    let records = rig.build_engine().recover_all().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].decision,
        RecoveryDecision::RetryReadyNeverDispatched
    );
    assert_eq!(rig.status(task_id), CheckpointStatus::RetryReady);
    assert_eq!(
        rig.task_state(task_id),
        TaskState::Running,
        "a provably undispatched step does not need to block the task"
    );
}

// ── Classification: Dispatched is always unknown ─────────────────────────────

#[test]
fn dispatched_idempotent_checkpoint_is_outcome_unknown_not_retryable() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Idempotent);
    rig.mark_dispatched(task_id, 0, &seeded);

    let records = rig.build_engine().recover_all().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, RecoveryDecision::OutcomeUnknown);
    assert_eq!(
        rig.status(task_id),
        CheckpointStatus::OutcomeUnknown,
        "an idempotent declaration does not prove the attempt did not happen"
    );
    assert_eq!(
        rig.task_state(task_id),
        TaskState::Blocked,
        "an uncertain external outcome must park the task"
    );
    assert!(
        rig.checkpoint_store.list_retry_ready().unwrap().is_empty(),
        "no dispatched checkpoint may become retryable by classification alone"
    );
}

#[test]
fn dispatched_at_most_once_checkpoint_is_outcome_unknown_not_failed() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.mark_dispatched(task_id, 0, &seeded);

    let records = rig.build_engine().recover_all().unwrap();
    assert_eq!(records[0].decision, RecoveryDecision::OutcomeUnknown);
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
    assert_eq!(rig.task_state(task_id), TaskState::Blocked);
}

#[test]
fn dispatched_reconcilable_checkpoint_is_outcome_unknown() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);
    rig.mark_dispatched(task_id, 0, &seeded);

    let records = rig.build_engine().recover_all().unwrap();
    assert_eq!(records[0].decision, RecoveryDecision::OutcomeUnknown);
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn terminal_checkpoints_are_not_recovered() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Idempotent);
    rig.mark_dispatched(task_id, 0, &seeded);

    let conn = rig.checkpoint_store.connection().unwrap();
    CheckpointStore::mark_succeeded(&conn, task_id, 0).unwrap();

    let records = rig.build_engine().recover_all().unwrap();
    assert!(
        records.is_empty(),
        "Succeeded checkpoints must not be recovered"
    );
}

#[test]
fn repeated_recovery_is_idempotent() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::Idempotent);

    let engine = rig.build_engine();
    assert_eq!(engine.recover_all().unwrap().len(), 1);
    assert!(
        engine.recover_all().unwrap().is_empty(),
        "a classified checkpoint must not be reported twice"
    );

    let events = rig
        .event_bus
        .get_events_for_task(&task_id.to_string())
        .unwrap();
    let recovered = events
        .iter()
        .filter(|event| event.event_type == "InvocationRecovered")
        .count();
    assert_eq!(recovered, 1, "recovery must not duplicate its audit events");
}

#[test]
fn failed_recovery_audit_rolls_back_the_classification() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.mark_dispatched(task_id, 0, &seeded);

    let connection = rig.checkpoint_store.connection().unwrap();
    connection.execute_batch("DROP TABLE events").unwrap();
    drop(connection);

    assert!(rig.build_engine().recover_all().is_err());
    assert_eq!(
        rig.status(task_id),
        CheckpointStatus::Dispatched,
        "an unauditable recovery must not leave a half-applied classification"
    );
    assert_eq!(rig.task_state(task_id), TaskState::Running);
}

#[test]
fn multiple_tasks_are_classified_independently() {
    let rig = RecoveryRig::new();

    let pending_task = rig.make_running_task();
    rig.seed_default_pending(pending_task, 0, SideEffectSemantics::AtMostOnce);

    let dispatched_task = rig.make_running_task();
    let seeded = rig.seed_default_pending(dispatched_task, 0, SideEffectSemantics::Idempotent);
    rig.mark_dispatched(dispatched_task, 0, &seeded);

    let records = rig.build_engine().recover_all().unwrap();
    assert_eq!(records.len(), 2);

    assert_eq!(rig.status(pending_task), CheckpointStatus::RetryReady);
    assert_eq!(
        rig.status(dispatched_task),
        CheckpointStatus::OutcomeUnknown
    );
    assert_eq!(rig.task_state(pending_task), TaskState::Running);
    assert_eq!(rig.task_state(dispatched_task), TaskState::Blocked);
}

// ── Reconciliation: the only way out of OutcomeUnknown ───────────────────────

#[test]
fn observed_effect_marks_the_step_succeeded() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));
    let outcome = rig.reconcile_git(&engine, task_id, 0).unwrap();

    assert_eq!(outcome, ReconcileOutcome::MarkedSucceeded);
    assert_eq!(rig.status(task_id), CheckpointStatus::Succeeded);

    let records = rig.reconciliation_store.list_for_task(task_id).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].actor_id, "recovery-agent");
    assert_eq!(records[0].actor_kind, "Operator");
    assert_eq!(records[0].auth_method, "HarnessOnly");
    assert_eq!(records[0].verdict, "ConfirmedSucceeded");
    assert_eq!(records[0].evidence_kind, "GitCommit");
    assert_eq!(
        records[0].action,
        ReconciliationAction::AdoptExistingArtifact
    );
    assert_eq!(records[0].prior_status, "OutcomeUnknown");
    assert_eq!(records[0].new_status, "Succeeded");
    assert_eq!(records[0].invocation_id, Some(seeded.invocation_id));
    assert!(records[0].grant_id.is_some());
}

#[test]
fn proven_absent_effect_authorizes_a_retry() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    rig.stage_observation(serde_json::json!({ "matching_commits": 0 }));
    let outcome = rig.reconcile_git(&engine, task_id, 0).unwrap();

    assert_eq!(outcome, ReconcileOutcome::RetryAuthorized);
    assert_eq!(rig.status(task_id), CheckpointStatus::RetryReady);
    assert_eq!(
        rig.reconciliation_store.list_for_task(task_id).unwrap()[0].action,
        ReconciliationAction::AuthorizeRetry
    );
}

#[test]
fn indeterminate_evidence_leaves_the_step_unknown() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    // Two commits match the intent: the runtime cannot attribute which one is
    // this invocation's effect.
    rig.stage_observation(serde_json::json!({ "matching_commits": 2 }));
    let outcome = rig.reconcile_git(&engine, task_id, 0).unwrap();

    assert!(matches!(outcome, ReconcileOutcome::RemainsUnknown { .. }));
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
    let record = &rig.reconciliation_store.list_for_task(task_id).unwrap()[0];
    assert_eq!(record.action, ReconciliationAction::Indeterminate);
    assert_eq!(record.verdict, "Indeterminate");
}

#[test]
fn a_probe_that_observes_nothing_cannot_unblock_a_retry() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    // No observation staged: the probe returns `{}`, which carries no
    // matching-commit count. Absence must never be inferred from silence.
    let outcome = rig.reconcile_git(&engine, task_id, 0).unwrap();

    assert!(matches!(outcome, ReconcileOutcome::RemainsUnknown { .. }));
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn reconciliation_refuses_a_step_that_is_not_unknown() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = rig.reconcile_git(&engine, task_id, 0).unwrap_err();
    assert!(matches!(
        error,
        kernel::recovery::RecoveryError::NotOutcomeUnknown { .. }
    ));
}

// ── Phase 5.2: fresh grant re-authorization ─────────────────────────────────

#[test]
fn retry_requires_a_fresh_grant_scoped_to_the_recorded_intent() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let pre_crash_grant = rig.issue_grant(task_id);
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    // The old in-memory grant is irrelevant: recovery mints its own.
    rig.grant_issuer.revoke_grant(&pre_crash_grant).unwrap();

    let permit = engine.prepare_retry(task_id, 0, "recovery-agent").unwrap();

    assert_ne!(
        permit.grant.grant_id, pre_crash_grant,
        "recovery must issue a fresh grant rather than resurrect the old one"
    );
    assert_eq!(permit.grant.task_id, task_id);
    assert_eq!(permit.grant.agent_id, "recovery-agent");
    assert_eq!(
        permit.grant.capabilities,
        vec![Capability::FileSystemWrite {
            root: rig.workspace_root.clone()
        }],
        "the fresh grant is narrowed to exactly the recorded capability intent"
    );
    assert!(permit.grant.is_valid());
    let ttl = permit.grant.expires_at - permit.grant.issued_at;
    assert!(
        ttl <= chrono::Duration::hours(1),
        "recovery grants must be short-lived, got {ttl}"
    );
    assert_eq!(permit.policy_id, rig.policy.policy_id());
    assert_eq!(permit.policy_version, rig.policy.version());
}

#[test]
fn permit_binds_to_the_recorded_invocation_identity() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();
    let permit = engine.prepare_retry(task_id, 0, "recovery-agent").unwrap();

    assert_eq!(permit.step_number, 0);
    assert_eq!(permit.invocation_id, seeded.invocation_id);
    assert_eq!(permit.idempotency_key, seeded.idempotency_key);
    assert_eq!(permit.argument_fingerprint, seeded.argument_fingerprint);
}

#[test]
fn a_grant_is_never_issued_for_a_dispatched_outcome_unknown_step() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Idempotent);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();
    assert!(
        matches!(
            expect_authorization_error(error),
            AuthorizationError::NotRetryEligible { .. }
        ),
        "a task with an OutcomeUnknown step must not be authorized for retry"
    );
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn policy_tightening_while_offline_refuses_the_retry_and_fails_the_task() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.build_engine().recover_all().unwrap();

    // The policy changed while the runtime was down: writes are no longer
    // permitted, only reads.
    let tightened = Arc::new(policy_for_agent(
        "recovery-test-policy",
        2,
        "recovery-agent",
        [Capability::FileSystemRead {
            root: rig.workspace_root.clone(),
        }],
    ));

    let engine = rig.build_engine_with_policy(tightened);
    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();

    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::Refused { .. }
    ));
    assert_eq!(
        rig.task_state(task_id),
        TaskState::Failed,
        "a revoked grant on recovery must fail the task, not silently retry it"
    );

    let decisions = rig.authorization_store.list_decisions(task_id).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(!decisions[0].granted);
    assert_eq!(decisions[0].policy_version, 2);
    assert_eq!(
        decisions[0].requested_capabilities,
        vec![Capability::FileSystemWrite {
            root: rig.workspace_root.clone()
        }]
    );
}

#[test]
fn revoked_agent_cannot_be_reauthorized() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.build_engine().recover_all().unwrap();

    let policy = Arc::new(
        RecoveryRig::default_policy(&rig.workspace_root).with_revoked_agent("recovery-agent"),
    );
    let engine = rig.build_engine_with_policy(policy);

    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();
    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::Refused { .. }
    ));
    assert_eq!(rig.task_state(task_id), TaskState::Failed);
}

#[test]
fn agent_identity_mismatch_is_refused() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.build_engine().recover_all().unwrap();

    let error = rig
        .build_engine()
        .prepare_retry(task_id, 0, "impostor-agent")
        .unwrap_err();

    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::AgentIdentityMismatch { .. }
    ));
    let decisions = rig.authorization_store.list_decisions(task_id).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(!decisions[0].granted);
}

#[test]
fn missing_authorization_context_blocks_the_retry() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();

    // A checkpoint with invocation identity but no persisted capability intent
    // (e.g. written by a runtime that predates Phase 5.2).
    let conn = rig.checkpoint_store.connection().unwrap();
    CheckpointStore::write_pending_invocation(
        &conn,
        task_id,
        "recovery-agent",
        0,
        &CheckpointInvocation {
            invocation_id: Uuid::new_v4(),
            idempotency_key: "legacy-key".into(),
            argument_fingerprint: "legacy-fingerprint".into(),
            semantics: SideEffectSemantics::Idempotent,
            tool_id: "filesystem".into(),
            operation_id: "write_file".into(),
        },
    )
    .unwrap();
    drop(conn);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();
    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::MissingAuthorizationContext { .. }
    ));
}

#[test]
fn granted_authorization_is_persisted_and_audited() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();
    let permit = engine.prepare_retry(task_id, 0, "recovery-agent").unwrap();

    let decisions = rig.authorization_store.list_decisions(task_id).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0].granted);
    assert_eq!(decisions[0].grant_id, Some(permit.grant.grant_id));
    assert_eq!(decisions[0].policy_id, rig.policy.policy_id());

    let events = rig
        .event_bus
        .get_events_for_task(&task_id.to_string())
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "RecoveryAuthorizationGranted")
    );
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "CapabilitiesAuthorized")
    );
}

#[test]
fn obligations_report_pending_recovery_work() {
    let rig = RecoveryRig::new();
    let pending_task = rig.make_running_task();
    rig.seed_default_pending(pending_task, 0, SideEffectSemantics::AtMostOnce);

    let unknown_task = rig.make_running_task();
    let seeded = rig.seed_default_pending(unknown_task, 0, SideEffectSemantics::Idempotent);
    rig.mark_dispatched(unknown_task, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let pending_obligations = engine.obligations(pending_task).unwrap();
    assert_eq!(pending_obligations.retry_ready.len(), 1);
    assert!(pending_obligations.outcome_unknown.is_empty());
    assert!(pending_obligations.blocks_resumption());

    let unknown_obligations = engine.obligations(unknown_task).unwrap();
    assert_eq!(unknown_obligations.outcome_unknown.len(), 1);
    assert!(unknown_obligations.retry_ready.is_empty());
    assert!(unknown_obligations.blocks_resumption());
}

// ── Phase 5.2 refinement: runtime-derived capability requirements ────────────

#[test]
fn the_fresh_grant_is_narrowed_to_the_operation_requirement() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();

    // The step was authorized under a broad grant (filesystem + git), but the
    // pending operation is a git commit.  Recovery must authorize only what the
    // operation needs, even though the recorded intent was wider.
    rig.seed_pending(
        task_id,
        0,
        SideEffectSemantics::AtMostOnce,
        vec![
            Capability::FileSystemWrite {
                root: rig.workspace_root.clone(),
            },
            Capability::GitWrite {
                repo_root: rig.workspace_root.clone(),
            },
        ],
        "git",
        "commit",
        serde_json::json!({ "message": "narrow me" }),
    );

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let permit = engine.prepare_retry(task_id, 0, "recovery-agent").unwrap();
    assert_eq!(
        permit.grant.capabilities,
        vec![Capability::GitWrite {
            repo_root: rig.workspace_root.clone()
        }],
        "a re-authorized retry must carry only the authority the operation needs"
    );
}

#[test]
fn an_under_declared_capability_intent_is_refused() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();

    // The pending operation is a git commit, but the recorded intent carries
    // only filesystem authority.  An agent that under-declares its requirements
    // must not be re-authorized.
    rig.seed_pending(
        task_id,
        0,
        SideEffectSemantics::AtMostOnce,
        vec![Capability::FileSystemWrite {
            root: rig.workspace_root.clone(),
        }],
        "git",
        "commit",
        serde_json::json!({ "message": "under-declared" }),
    );

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();
    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::IntentDoesNotCoverOperation {
            required: CapabilityKind::GitWrite,
            ..
        }
    ));
    assert_eq!(rig.task_state(task_id), TaskState::Failed);
}

#[test]
fn an_underivable_capability_requirement_is_refused() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();

    // A runtime that predates capability derivation (or an unknown tool) leaves
    // the requirement empty.  Recovery refuses rather than guessing.
    rig.seed_pending(
        task_id,
        0,
        SideEffectSemantics::AtMostOnce,
        vec![Capability::FileSystemWrite {
            root: rig.workspace_root.clone(),
        }],
        "unregistered-tool",
        "do_something",
        serde_json::json!({}),
    );

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = engine
        .prepare_retry(task_id, 0, "recovery-agent")
        .unwrap_err();
    assert!(matches!(
        expect_authorization_error(error),
        AuthorizationError::CapabilityRequirementsUnderivable { .. }
    ));
}

// ── Phase 5.4: explicit, attributed re-queue ─────────────────────────────────

#[test]
fn requeue_is_refused_while_uncertainty_remains() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    let error = rig
        .requeue_task(&engine, task_id, "just put it back")
        .unwrap_err();
    assert!(matches!(error, RecoveryError::UnresolvedUncertainty { .. }));
    assert_eq!(
        rig.task_state(task_id),
        TaskState::Blocked,
        "re-queueing must never be a way to skip reconciliation"
    );

    let records = rig.reconciliation_store.list_for_task(task_id).unwrap();
    assert!(
        records.is_empty(),
        "a refused re-queue must not leave an audit record claiming it happened"
    );
}

#[test]
fn requeue_after_reconciliation_is_attributed_and_preserves_history() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::AtMostOnce);
    rig.mark_dispatched(task_id, 0, &seeded);

    let engine = rig.build_engine();
    engine.recover_all().unwrap();

    rig.stage_observation(serde_json::json!({ "matching_commits": 0 }));
    rig.reconcile_git(&engine, task_id, 0).unwrap();

    rig.requeue_task(&engine, task_id, "safe to continue")
        .unwrap();

    assert_eq!(rig.task_state(task_id), TaskState::Ready);

    let records = rig.reconciliation_store.list_for_task(task_id).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].action, ReconciliationAction::AuthorizeRetry);
    assert_eq!(records[1].action, ReconciliationAction::RequeueForExecution);
    assert_eq!(records[1].actor_id, "recovery-agent");
    assert_eq!(records[1].reason, "safe to continue");
    assert_eq!(records[1].prior_status, "Blocked");
    assert_eq!(records[1].new_status, "Ready");
    assert_eq!(records[1].actor_kind, "Operator");

    // The original attempt is still legible: reconciliation advanced the status
    // but never rewrote the invocation identity.
    let checkpoint = rig
        .checkpoint_store
        .latest_for_task(task_id)
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.status, CheckpointStatus::RetryReady);
    assert_eq!(checkpoint.invocation_id, Some(seeded.invocation_id));
    assert_eq!(
        checkpoint.idempotency_key.as_deref(),
        Some(seeded.idempotency_key.as_str())
    );
}

#[test]
fn requeue_of_a_task_that_is_not_blocked_is_refused() {
    let rig = RecoveryRig::new();
    let task_id = rig.make_running_task();
    let engine = rig.build_engine();

    let error = rig.requeue_task(&engine, task_id, "no reason").unwrap_err();
    assert!(matches!(error, RecoveryError::TaskNotBlocked { .. }));
}

// ── Phase 6.0: adversarial governed reconciliation ───────────────────────────

/// A dispatched checkpoint blocked and ready to be reconciled.
fn blocked_task(rig: &RecoveryRig) -> (Uuid, SeededInvocation) {
    let task_id = rig.make_running_task();
    let seeded = rig.seed_default_pending(task_id, 0, SideEffectSemantics::Reconcilable);
    rig.mark_dispatched(task_id, 0, &seeded);
    rig.build_engine().recover_all().unwrap();
    (task_id, seeded)
}

#[test]
fn agent_actor_cannot_reconcile_its_own_operation() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);

    // The engine authenticates this claim as an *agent* even though the grant
    // is valid and names the right task.
    let engine = rig.build_engine_as(rig.policy.clone(), ActorKind::Agent);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    let error = rig
        .reconcile_git_with_claim(&engine, task_id, 0, ActorClaim::agent("recovery-agent"))
        .unwrap_err();
    assert!(
        matches!(error, RecoveryError::AgentSelfReconciliation { ref kind, .. } if kind == "Agent"),
        "an agent must never reconcile, got {error:?}"
    );
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
    assert!(
        rig.reconciliation_store
            .list_for_task(task_id)
            .unwrap()
            .is_empty(),
        "a refused agent reconciliation must not be recorded as a decision"
    );
}

#[test]
fn reconciliation_capability_is_scoped_to_one_task() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    let other_task = rig.make_running_task();
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    // Authority for `other_task` must not reconcile `task_id`.
    let wrong_scope = rig.grant_issuer.issue_grant(
        "recovery-agent",
        other_task,
        vec![Capability::SystemReconciliation {
            task_id: other_task,
        }],
        None,
    );
    let request = ReconciliationRequest::new(
        task_id,
        0,
        rig.recorded_invocation(task_id, 0),
        "wrong scope",
        EvidenceSpec::GitCommitAfterBaseline {
            repo_root: rig.workspace_root.clone(),
            baseline_commit: BASELINE.to_string(),
            intent_message: INTENT.to_string(),
        },
    );

    let error = rig
        .build_engine()
        .reconcile(
            &ActorClaim::process(ActorKind::Operator),
            &wrong_scope,
            &request,
        )
        .unwrap_err();

    assert!(matches!(error, RecoveryError::AuthorizationDenied { .. }));
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn a_grant_issued_to_another_actor_cannot_be_borrowed() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    let foreign_grant = rig.grant_issuer.issue_grant(
        "somebody-else",
        task_id,
        vec![Capability::SystemReconciliation { task_id }],
        None,
    );
    let request = ReconciliationRequest::new(
        task_id,
        0,
        rig.recorded_invocation(task_id, 0),
        "borrowed grant",
        EvidenceSpec::GitCommitAfterBaseline {
            repo_root: rig.workspace_root.clone(),
            baseline_commit: BASELINE.to_string(),
            intent_message: INTENT.to_string(),
        },
    );

    let error = rig
        .build_engine()
        .reconcile(
            &ActorClaim::process(ActorKind::Operator),
            &foreign_grant,
            &request,
        )
        .unwrap_err();
    assert!(matches!(error, RecoveryError::GrantActorMismatch { .. }));
}

#[test]
fn an_expired_reconciliation_grant_is_refused() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    let expired = rig.grant_issuer.issue_grant(
        "recovery-agent",
        task_id,
        vec![Capability::SystemReconciliation { task_id }],
        Some(chrono::Duration::seconds(-1)),
    );
    let request = ReconciliationRequest::new(
        task_id,
        0,
        rig.recorded_invocation(task_id, 0),
        "expired",
        EvidenceSpec::GitCommitAfterBaseline {
            repo_root: rig.workspace_root.clone(),
            baseline_commit: BASELINE.to_string(),
            intent_message: INTENT.to_string(),
        },
    );

    let error = rig
        .build_engine()
        .reconcile(
            &ActorClaim::process(ActorKind::Operator),
            &expired,
            &request,
        )
        .unwrap_err();
    assert!(matches!(error, RecoveryError::GrantInactive));
}

#[test]
fn a_caller_cannot_nominate_a_baseline_the_runtime_never_recorded() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 0 }));

    let grant = rig.reconciliation_grant(task_id);
    // A baseline taken *after* the effect would make an empty range look like
    // proof of absence. The engine must reject it.
    let request = ReconciliationRequest::new(
        task_id,
        0,
        rig.recorded_invocation(task_id, 0),
        "convenient baseline",
        EvidenceSpec::GitCommitAfterBaseline {
            repo_root: rig.workspace_root.clone(),
            baseline_commit: "later-head-sha".to_string(),
            intent_message: INTENT.to_string(),
        },
    );

    let error = rig
        .build_engine()
        .reconcile(&ActorClaim::process(ActorKind::Operator), &grant, &request)
        .unwrap_err();
    assert!(matches!(error, RecoveryError::BaselineMismatch { .. }));
    assert_eq!(rig.status(task_id), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn reconciliation_without_a_probe_is_refused() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    let engine = RecoveryEngine::new(RecoveryServices {
        checkpoint_store: rig.checkpoint_store.clone(),
        task_store: rig.task_store.clone(),
        event_bus: rig.event_bus.clone(),
        grant_issuer: rig.grant_issuer.clone(),
        authorization_store: rig.authorization_store.clone(),
        reconciliation_store: rig.reconciliation_store.clone(),
        policy: rig.policy.clone(),
        authenticator: Arc::new(RigAuthenticator {
            kind: ActorKind::Operator,
        }),
        probes: Vec::new(),
    });

    let error = rig.reconcile_git(&engine, task_id, 0).unwrap_err();
    assert!(matches!(error, RecoveryError::NoProbeForKind { .. }));
}

#[test]
fn an_unauditable_reconciliation_changes_nothing() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    // Make the audit write fail: the verdict must not be applied without it.
    let conn = rig.checkpoint_store.connection().unwrap();
    conn.execute_batch("DROP TABLE events").unwrap();
    drop(conn);

    let error = rig
        .reconcile_git(&rig.build_engine(), task_id, 0)
        .unwrap_err();
    assert!(matches!(error, RecoveryError::Event(_)));
    assert_eq!(
        rig.status(task_id),
        CheckpointStatus::OutcomeUnknown,
        "an unauditable verdict must not advance the checkpoint"
    );
    assert!(
        rig.reconciliation_store
            .list_for_task(task_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reconciliation_records_authenticated_provenance() {
    let rig = RecoveryRig::new();
    let (task_id, _) = blocked_task(&rig);
    rig.stage_observation(serde_json::json!({ "matching_commits": 1 }));

    rig.reconcile_git(&rig.build_engine(), task_id, 0).unwrap();

    let record = &rig.reconciliation_store.list_for_task(task_id).unwrap()[0];
    assert_eq!(record.actor_id, "recovery-agent");
    assert_eq!(record.actor_kind, "Operator");
    assert_eq!(record.auth_method, "HarnessOnly");
    assert_eq!(record.verdict, "ConfirmedSucceeded");
    assert_eq!(record.evidence_kind, "GitCommit");
    assert!(
        !record.evidence_json.is_empty(),
        "the raw observation must be preserved, not just the verdict"
    );
    assert!(record.grant_id.is_some());
    assert!(
        record.evidence.contains(BASELINE),
        "the record must show which baseline bounded the observation"
    );
}
