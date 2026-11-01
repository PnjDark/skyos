/// Phase 5 — Crash Recovery & Execution Semantics.
///
/// `RecoveryEngine` is the kernel-level component that classifies interrupted
/// invocations and applies the correct recovery strategy on restart.
///
/// # The epistemic rule
///
/// A checkpoint describes **what the runtime knows** about an operation.  It
/// does not, by itself, prove what happened in the external world.  Every
/// recovery decision below is derived from that distinction:
///
/// - `Pending` proves the tool was never invoked, so a retry is semantically
///   safe.
/// - `Dispatched` proves only that an attempt *may* have reached the outside
///   world.  It is therefore always classified `OutcomeUnknown` and the task is
///   parked in `Blocked`.  It is never converted directly into a retryable
///   state, regardless of the operation's declared idempotency.
///
/// # Recovery invariants
///
/// 1. **Never assume an interrupted dispatch did not happen.**  `OutcomeUnknown`
///    requires physical reconciliation before re-execution.
/// 2. **Retryability is not authorization.**  A `RetryReady` checkpoint may
///    still only be executed after `RecoveryAuthorizer` re-establishes a fresh
///    grant against the current policy (Phase 5.2).
/// 3. **Recovery is itself idempotent** — repeated passes classify each row at
///    most once and produce no duplicate side effects.
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use thiserror::Error;
use uuid::Uuid;

use crate::events::EventBus;
use crate::identity::{ActorAuthenticator, ActorClaim, ActorKind, AuthenticatedActor};
use crate::permissions::engine::PolicyEngine;
use crate::permissions::issuer::GrantIssuer;
use crate::permissions::policy::AuthorizationPolicy;
use crate::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use crate::tasks::checkpoint::{
    CheckpointError, CheckpointStatus, CheckpointStore, SideEffectSemantics, TaskCheckpoint,
};
use crate::tasks::state::TaskState;
use crate::tasks::store::{TaskStore, TaskStoreError};

pub mod authorization;
pub mod evidence;
pub mod reconciliation;

pub use authorization::{
    AuthorizationContext, AuthorizationDecisionRecord, AuthorizationError, AuthorizationStore,
    EVENT_REAUTHORIZATION_DENIED, EVENT_REAUTHORIZATION_GRANTED, RECOVERY_GRANT_TTL_SECONDS,
    RecoveryAuthorization, RecoveryAuthorizer,
};
pub use evidence::{
    EvidenceKind, EvidenceProbe, EvidenceRef, EvidenceSpec, ProbeContext, ProbeError,
    ReconciliationVerdict,
};
pub use reconciliation::{
    ReconciliationAction, ReconciliationError, ReconciliationRecord, ReconciliationStore,
};

pub const EVENT_INVOCATION_RECOVERED: &str = "InvocationRecovered";
pub const EVENT_INVOCATION_RECONCILED: &str = "InvocationReconciled";
pub const EVENT_TASK_REQUEUED: &str = "TaskRequeuedAfterReconciliation";

// ── Public types ──────────────────────────────────────────────────────────────

/// How the recovery engine classified and handled an interrupted invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// A `Pending` checkpoint was found: the tool was provably never invoked.
    /// The row is marked `RetryReady`; execution still requires authorization.
    RetryReadyNeverDispatched,
    /// A `Dispatched` checkpoint was found: the external outcome is unknown.
    /// The row is marked `OutcomeUnknown` and the task is `Blocked`.
    OutcomeUnknown,
}

/// Full record of a single recovery action.
#[derive(Debug, Clone)]
pub struct RecoveryRecord {
    pub task_id: Uuid,
    pub step_number: usize,
    pub tool_id: Option<String>,
    pub operation_id: Option<String>,
    pub semantics: SideEffectSemantics,
    pub prior_status: CheckpointStatus,
    pub decision: RecoveryDecision,
    pub recovered_at: String,
}

/// An attributed request to resolve an uncertain step.
///
/// The caller names **what to observe**; it cannot supply a verdict. The
/// runtime selects a probe, collects the fact, and derives the verdict itself.
/// (Phase 5 accepted a caller-supplied `EffectObserved`/`EffectAbsent` verdict;
/// that type is gone from the API on purpose.)
#[derive(Debug, Clone)]
pub struct ReconciliationRequest {
    pub task_id: Uuid,
    pub step_number: usize,
    /// The invocation the operator believes they are reconciling. Checked
    /// against the persisted checkpoint before any probe runs, so a stale or
    /// mistyped identifier cannot resolve the wrong execution.
    pub invocation_id: Uuid,
    /// Why the operator is resolving this step now. Recorded verbatim.
    pub reason: String,
    /// The observation to perform. Never a conclusion.
    pub evidence: EvidenceSpec,
}

impl ReconciliationRequest {
    pub fn new(
        task_id: Uuid,
        step_number: usize,
        invocation_id: Uuid,
        reason: impl Into<String>,
        evidence: EvidenceSpec,
    ) -> Self {
        Self {
            task_id,
            step_number,
            invocation_id,
            reason: reason.into(),
            evidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Evidence proved the effect happened; the checkpoint is `Succeeded`.
    MarkedSucceeded,
    /// Evidence proved the effect did not happen; the checkpoint is
    /// `RetryReady` and may now be re-authorized.
    RetryAuthorized,
    /// No verdict could be reached; the checkpoint stays `OutcomeUnknown`.
    RemainsUnknown { reason: String },
}

/// Proof that a `RetryReady` step may be dispatched again.
///
/// A permit is the *only* thing that lets an executor re-dispatch an
/// interrupted step.  It binds the fresh grant to the exact invocation
/// identity (step, invocation id, idempotency key, argument fingerprint) that
/// was recorded before the crash.
#[derive(Debug, Clone)]
pub struct RetryPermit {
    pub task_id: Uuid,
    pub step_number: usize,
    pub invocation_id: Uuid,
    pub idempotency_key: String,
    pub argument_fingerprint: String,
    pub grant: CapabilityGrant,
    pub policy_id: String,
    pub policy_version: u64,
    pub issued_at: chrono::DateTime<Utc>,
}

/// What a task still owes the recovery process before it may resume.
#[derive(Debug, Clone, Default)]
pub struct TaskRecoveryObligations {
    /// Steps approved for retry, but not yet authorized for execution.
    pub retry_ready: Vec<TaskCheckpoint>,
    /// Steps whose external outcome is unknown.
    pub outcome_unknown: Vec<TaskCheckpoint>,
}

impl TaskRecoveryObligations {
    pub fn blocks_resumption(&self) -> bool {
        !self.retry_ready.is_empty() || !self.outcome_unknown.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("task store error: {0}")]
    TaskStore(#[from] TaskStoreError),
    #[error("event emission failed: {0}")]
    Event(#[from] crate::events::EventError),
    #[error("database error: {0}")]
    Database(#[from] crate::persistence::db::DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("authorization error: {0}")]
    Authorization(#[from] AuthorizationError),
    #[error("unexpected checkpoint status during recovery: {0}")]
    UnexpectedCheckpointStatus(String),
    #[error("checkpoint {task_id}/{step_number} not found")]
    CheckpointNotFound { task_id: Uuid, step_number: usize },
    #[error("checkpoint {task_id}/{step_number} is {status}, not OutcomeUnknown")]
    NotOutcomeUnknown {
        task_id: Uuid,
        step_number: usize,
        status: String,
    },
    #[error("checkpoint {task_id}/{step_number} has no recorded invocation identity")]
    IncompleteCheckpoint { task_id: Uuid, step_number: usize },
    #[error("task {task_id} not found")]
    TaskNotFound { task_id: Uuid },
    #[error("task {task_id} is {state}, not Blocked; only a blocked task may be re-queued")]
    TaskNotBlocked { task_id: Uuid, state: String },
    #[error(
        "task {task_id} still has unresolved uncertainty at step(s) {steps}; reconcile it \
         before re-queueing"
    )]
    UnresolvedUncertainty { task_id: Uuid, steps: String },
    #[error("reconciliation error: {0}")]
    Reconciliation(#[from] crate::recovery::reconciliation::ReconciliationError),
    #[error("actor authentication failed: {0}")]
    Authentication(#[from] crate::identity::AuthError),
    #[error("actor '{id}' ({kind}) may not reconcile its own operation")]
    AgentSelfReconciliation { id: String, kind: String },
    #[error(
        "the presented grant belongs to agent '{grant_agent}', not the authenticated actor '{actor}'"
    )]
    GrantActorMismatch { grant_agent: String, actor: String },
    #[error("the presented grant is expired or revoked")]
    GrantInactive,
    #[error("authorization denied: {reason}")]
    AuthorizationDenied { reason: String },
    #[error("no evidence probe is registered for {kind}")]
    NoProbeForKind { kind: String },
    #[error("evidence probe failed: {0}")]
    Probe(#[from] crate::recovery::evidence::ProbeError),
    #[error(
        "requested baseline {requested} does not match the baseline {recorded} recorded before \
         dispatch; refusing to reconcile against an unrecorded baseline"
    )]
    BaselineMismatch { requested: String, recorded: String },
    #[error(
        "no pre-dispatch baseline was recorded for {task_id}/{step_number}; the effect cannot be bounded"
    )]
    MissingBaseline { task_id: Uuid, step_number: usize },
    #[error(
        "invocation {requested} does not match the invocation {recorded} recorded for \
         {task_id}/{step_number}"
    )]
    InvocationMismatch {
        task_id: Uuid,
        step_number: usize,
        requested: Uuid,
        recorded: String,
    },
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Kernel-level crash recovery coordinator.
pub struct RecoveryEngine {
    checkpoint_store: CheckpointStore,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
    authorization_store: AuthorizationStore,
    reconciliation_store: ReconciliationStore,
    policy: Arc<AuthorizationPolicy>,
    authenticator: Arc<dyn ActorAuthenticator>,
    probes: Vec<Arc<dyn EvidenceProbe>>,
}

/// Everything the recovery engine needs, bundled so the constructor stays
/// readable as the Phase 5/6 surface grows.
pub struct RecoveryServices {
    pub checkpoint_store: CheckpointStore,
    pub task_store: TaskStore,
    pub event_bus: EventBus,
    pub grant_issuer: GrantIssuer,
    pub authorization_store: AuthorizationStore,
    pub reconciliation_store: ReconciliationStore,
    pub policy: Arc<AuthorizationPolicy>,
    /// The trust anchor. `DenyAllAuthenticator` is the safe default.
    pub authenticator: Arc<dyn ActorAuthenticator>,
    /// Evidence mechanisms. An empty registry means reconciliation is refused.
    pub probes: Vec<Arc<dyn EvidenceProbe>>,
}

impl RecoveryEngine {
    pub fn new(services: RecoveryServices) -> Self {
        Self {
            checkpoint_store: services.checkpoint_store,
            task_store: services.task_store,
            event_bus: services.event_bus,
            grant_issuer: services.grant_issuer,
            authorization_store: services.authorization_store,
            reconciliation_store: services.reconciliation_store,
            policy: services.policy,
            authenticator: services.authenticator,
            probes: services.probes,
        }
    }

    /// Register evidence probes after construction. Callers that never
    /// reconcile can skip this; reconciliation then fails closed.
    pub fn with_probes(mut self, probes: Vec<Arc<dyn EvidenceProbe>>) -> Self {
        self.probes = probes;
        self
    }

    /// Convenience constructor: opens the checkpoint, authorization, and
    /// reconciliation stores from the same path as `TaskStore` (they share
    /// `runtime_state.db`).
    pub fn open(
        db_path: impl AsRef<Path>,
        task_store: TaskStore,
        event_bus: EventBus,
        grant_issuer: GrantIssuer,
        policy: Arc<AuthorizationPolicy>,
        authenticator: Arc<dyn ActorAuthenticator>,
    ) -> Result<Self, RecoveryError> {
        let path = db_path.as_ref();
        Ok(Self::new(RecoveryServices {
            checkpoint_store: CheckpointStore::open(path)?,
            authorization_store: AuthorizationStore::open(path)?,
            reconciliation_store: ReconciliationStore::open(path)?,
            task_store,
            event_bus,
            grant_issuer,
            policy,
            authenticator,
            probes: Vec::new(),
        }))
    }

    pub fn checkpoint_store(&self) -> &CheckpointStore {
        &self.checkpoint_store
    }

    pub fn authorization_store(&self) -> &AuthorizationStore {
        &self.authorization_store
    }

    pub fn reconciliation_store(&self) -> &ReconciliationStore {
        &self.reconciliation_store
    }

    pub fn policy(&self) -> &AuthorizationPolicy {
        &self.policy
    }

    /// Authorizer bound to this engine's live policy and stores.
    pub fn authorizer(&self) -> RecoveryAuthorizer<'_> {
        RecoveryAuthorizer::new(
            &self.policy,
            &self.grant_issuer,
            &self.task_store,
            &self.event_bus,
            &self.checkpoint_store,
            &self.authorization_store,
        )
    }

    // ── Classification ────────────────────────────────────────────────────────

    /// On process startup, classify every `Pending` and `Dispatched`
    /// checkpoint.  Classification never authorizes execution.
    ///
    /// Returns one `RecoveryRecord` per affected checkpoint.
    pub fn recover_all(&self) -> Result<Vec<RecoveryRecord>, RecoveryError> {
        let unresolved = self.checkpoint_store.list_unresolved()?;
        let mut records = Vec::with_capacity(unresolved.len());

        for checkpoint in unresolved {
            records.push(self.recover_one(&checkpoint)?);
        }

        Ok(records)
    }

    fn recover_one(&self, cp: &TaskCheckpoint) -> Result<RecoveryRecord, RecoveryError> {
        let recovered_at = Utc::now().to_rfc3339();
        let mut connection = self.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;

        let decision = match &cp.status {
            // Provably never dispatched: nothing reached the outside world.
            CheckpointStatus::Pending => {
                CheckpointStore::mark_retry_ready_from_pending(
                    &transaction,
                    cp.task_id,
                    cp.step_number,
                )?;
                self.emit_recovery_event_with_connection(
                    &transaction,
                    cp,
                    "Pending checkpoint proves the tool was never invoked; \
                     marked RetryReady. Execution still requires re-authorization.",
                )?;
                RecoveryDecision::RetryReadyNeverDispatched
            }

            // An attempt may have reached the outside world.  The runtime must
            // not guess: park the step and the task.
            CheckpointStatus::Dispatched => {
                CheckpointStore::mark_outcome_unknown(&transaction, cp.task_id, cp.step_number)?;
                self.transition_task_if_running(&transaction, cp.task_id, TaskState::Blocked)?;
                self.emit_recovery_event_with_connection(
                    &transaction,
                    cp,
                    "Dispatched checkpoint has an unknown external outcome; \
                     marked OutcomeUnknown and blocked the task pending reconciliation.",
                )?;
                RecoveryDecision::OutcomeUnknown
            }

            other => {
                return Err(RecoveryError::UnexpectedCheckpointStatus(
                    other.as_str().to_string(),
                ));
            }
        };

        transaction.commit()?;

        Ok(RecoveryRecord {
            task_id: cp.task_id,
            step_number: cp.step_number,
            tool_id: cp.tool_id.clone(),
            operation_id: cp.operation_id.clone(),
            semantics: cp.semantics.clone(),
            prior_status: cp.status.clone(),
            decision,
            recovered_at,
        })
    }

    // ── Reconciliation ────────────────────────────────────────────────────────

    /// Authenticate a claim, then check the caller presented a grant that
    /// actually authorizes reconciling `task_id`.
    ///
    /// Three independent barriers, any one of which is sufficient:
    /// an agent actor is refused outright, the grant must belong to the
    /// authenticated actor, and the policy engine must find a
    /// `SystemReconciliation { task_id }` capability covering this task.
    fn authorize_reconciliation(
        &self,
        claim: &ActorClaim,
        grant: &CapabilityGrant,
        task_id: Uuid,
        action: &str,
    ) -> Result<AuthenticatedActor, RecoveryError> {
        let actor = AuthenticatedActor::from_verified(self.authenticator.verify(claim)?);

        // Barrier 1: agents never reconcile, regardless of what they hold.
        if actor.kind() == ActorKind::Agent {
            return Err(RecoveryError::AgentSelfReconciliation {
                id: actor.id().to_string(),
                kind: actor.kind().as_str().to_string(),
            });
        }

        // Barrier 2: a grant is only usable by the actor it was issued to.
        if grant.agent_id != actor.id() {
            return Err(RecoveryError::GrantActorMismatch {
                grant_agent: grant.agent_id.clone(),
                actor: actor.id().to_string(),
            });
        }
        if !grant.is_active() {
            return Err(RecoveryError::GrantInactive);
        }

        // Barrier 3: the capability must cover exactly this task, checked
        // through the audited policy engine.
        let request = ToolInvocationRequest::SystemReconciliation {
            task_id,
            action: action.to_string(),
        };
        let decision =
            PolicyEngine::new(Some(&self.event_bus)).evaluate_checked(grant, &request)?;
        if let PolicyDecision::Deny { reason } = decision {
            return Err(RecoveryError::AuthorizationDenied { reason });
        }

        Ok(actor)
    }

    /// Resolve an `OutcomeUnknown` step from **independently collected**
    /// evidence.
    ///
    /// The caller names an observation; the runtime runs the matching probe and
    /// derives the verdict. It never re-executes anything; it either accepts
    /// that the effect happened, proves it did not (which makes a re-authorized
    /// retry possible), or leaves the step unknown.
    ///
    /// Every attempt — including an inconclusive one — is attributed and
    /// persisted. The checkpoint's identity columns are never rewritten; only
    /// its status advances, and the prior status is preserved in the
    /// reconciliation record.
    pub fn reconcile(
        &self,
        claim: &ActorClaim,
        grant: &CapabilityGrant,
        request: &ReconciliationRequest,
    ) -> Result<ReconcileOutcome, RecoveryError> {
        let task_id = request.task_id;
        let step_number = request.step_number;
        let actor = self.authorize_reconciliation(claim, grant, task_id, "reconcile")?;

        let checkpoint = self.checkpoint_store.get(task_id, step_number)?.ok_or(
            RecoveryError::CheckpointNotFound {
                task_id,
                step_number,
            },
        )?;

        if checkpoint.status != CheckpointStatus::OutcomeUnknown {
            return Err(RecoveryError::NotOutcomeUnknown {
                task_id,
                step_number,
                status: checkpoint.status.as_str().to_string(),
            });
        }

        // The supplied identifiers must name the same persisted execution. This
        // runs before any probe so a mistyped invocation cannot resolve another
        // attempt's outcome.
        match checkpoint.invocation_id {
            Some(recorded) if recorded == request.invocation_id => {}
            recorded => {
                return Err(RecoveryError::InvocationMismatch {
                    task_id,
                    step_number,
                    requested: request.invocation_id,
                    recorded: recorded
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                });
            }
        }

        // The observation must be bounded by what the runtime recorded before
        // dispatch. A caller may not nominate its own baseline.
        let recorded_baseline = self.recorded_baseline(task_id, step_number)?;
        if let EvidenceSpec::GitCommitAfterBaseline {
            baseline_commit, ..
        } = &request.evidence
        {
            match recorded_baseline.as_deref() {
                Some(recorded) if recorded != baseline_commit => {
                    return Err(RecoveryError::BaselineMismatch {
                        requested: baseline_commit.clone(),
                        recorded: recorded.to_string(),
                    });
                }
                None => {
                    return Err(RecoveryError::MissingBaseline {
                        task_id,
                        step_number,
                    });
                }
                _ => {}
            }
        }

        let ctx = ProbeContext {
            task_id,
            step_number,
            recorded_baseline,
        };
        let evidence = self.collect_evidence(&request.evidence, &ctx)?;
        let verdict = crate::recovery::evidence::evaluate(&request.evidence, &evidence);

        let mut connection = self.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;

        let (outcome, action, new_status) = match &verdict {
            ReconciliationVerdict::ConfirmedSucceeded { .. } => {
                CheckpointStore::mark_succeeded(&transaction, task_id, step_number)?;
                (
                    ReconcileOutcome::MarkedSucceeded,
                    ReconciliationAction::AdoptExistingArtifact,
                    CheckpointStatus::Succeeded,
                )
            }
            ReconciliationVerdict::ConfirmedNotExecuted { .. } => {
                CheckpointStore::mark_authorized_retry_ready(&transaction, task_id, step_number)?;
                (
                    ReconcileOutcome::RetryAuthorized,
                    ReconciliationAction::AuthorizeRetry,
                    CheckpointStatus::RetryReady,
                )
            }
            ReconciliationVerdict::Indeterminate { reason } => (
                ReconcileOutcome::RemainsUnknown {
                    reason: reason.clone(),
                },
                ReconciliationAction::Indeterminate,
                CheckpointStatus::OutcomeUnknown,
            ),
        };

        let now = Utc::now();
        ReconciliationStore::record_with_connection(
            &transaction,
            &ReconciliationRecord {
                reconciliation_id: Uuid::new_v4(),
                task_id,
                step_number,
                actor_id: actor.id().to_string(),
                action,
                reason: request.reason.clone(),
                evidence: format!("{} -> {}", request.evidence.describe(), evidence.summary()),
                prior_status: checkpoint.status.as_str().to_string(),
                new_status: new_status.as_str().to_string(),
                created_at: now.to_rfc3339(),
                invocation_id: checkpoint.invocation_id,
                verdict: verdict.as_str().to_string(),
                evidence_kind: evidence.kind.as_str().to_string(),
                evidence_source: evidence.source.clone(),
                evidence_json: serde_json::to_string(&evidence.observed).unwrap_or_default(),
                actor_kind: actor.kind().as_str().to_string(),
                auth_method: actor.method().as_str().to_string(),
                grant_id: Some(grant.grant_id),
            },
        )?;

        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            EVENT_INVOCATION_RECONCILED,
            serde_json::json!({
                "task_id": task_id,
                "step_number": step_number,
                "tool_id": checkpoint.tool_id,
                "operation_id": checkpoint.operation_id,
                "semantics": checkpoint.semantics.as_str(),
                "actor_id": actor.id(),
                "actor_kind": actor.kind().as_str(),
                "auth_method": actor.method().as_str(),
                "grant_id": grant.grant_id,
                "reason": request.reason,
                "requested_evidence": request.evidence.describe(),
                "evidence_source": evidence.source,
                "observation": evidence.observed,
                "verdict": verdict.as_str(),
                "action": action.as_str(),
                "prior_status": checkpoint.status.as_str(),
            }),
        )?;

        transaction.commit()?;
        Ok(outcome)
    }

    /// The baseline the runtime recorded before dispatch, if any.
    ///
    /// Phase 6.0 reads it from the `ToolInvocationDispatched` event, which is
    /// written in the same transaction as the dispatch checkpoint. Phase 6.1
    /// will promote it into the authorization context.
    ///
    /// Public so an operator command can show (or default to) the same baseline
    /// the engine will enforce — the value is never trusted from the caller.
    pub fn recorded_baseline(
        &self,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<Option<String>, RecoveryError> {
        let events = self.event_bus.get_events_for_task(&task_id.to_string())?;
        let baseline = events
            .iter()
            .filter(|event| event.event_type == "ToolInvocationDispatched")
            .filter(|event| {
                event
                    .payload
                    .get("step_number")
                    .and_then(|value| value.as_u64())
                    .map(|step| step as usize)
                    == Some(step_number)
            })
            .filter_map(|event| {
                event
                    .payload
                    .get("baseline_head")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
            .next_back();
        Ok(baseline)
    }

    fn collect_evidence(
        &self,
        spec: &EvidenceSpec,
        ctx: &ProbeContext,
    ) -> Result<EvidenceRef, RecoveryError> {
        let kind = spec.kind();
        let probe = self
            .probes
            .iter()
            .find(|probe| probe.kind() == kind)
            .ok_or_else(|| RecoveryError::NoProbeForKind {
                kind: kind.as_str().to_string(),
            })?;
        Ok(probe.probe(spec, ctx)?)
    }

    /// Put a `Blocked` task back in the queue.
    ///
    /// This is the explicit operator decision the recovery model requires: a
    /// task blocked by an uncertain dispatch must not resume merely because the
    /// process restarted.  Re-queueing is refused while any step is still
    /// `OutcomeUnknown` — reconciliation must come first — and it is recorded
    /// as an attributed action, never as evidence that the original side effect
    /// failed.
    pub fn requeue(
        &self,
        claim: &ActorClaim,
        grant: &CapabilityGrant,
        task_id: Uuid,
        reason: &str,
    ) -> Result<(), RecoveryError> {
        let actor = self.authorize_reconciliation(claim, grant, task_id, "requeue")?;

        let task = self
            .task_store
            .get_task(&task_id)?
            .ok_or(RecoveryError::TaskNotFound { task_id })?;

        if task.state != TaskState::Blocked {
            return Err(RecoveryError::TaskNotBlocked {
                task_id,
                state: task.state.to_string(),
            });
        }

        let obligations = self.obligations(task_id)?;
        if !obligations.outcome_unknown.is_empty() {
            let steps = obligations
                .outcome_unknown
                .iter()
                .map(|checkpoint| checkpoint.step_number.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(RecoveryError::UnresolvedUncertainty { task_id, steps });
        }

        let step_number = obligations
            .retry_ready
            .iter()
            .map(|checkpoint| checkpoint.step_number)
            .max()
            .unwrap_or(0);

        let mut connection = self.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;

        self.task_store.transition_state_with_connection(
            &transaction,
            task_id,
            TaskState::Blocked,
            TaskState::Ready,
        )?;

        let now = Utc::now();
        ReconciliationStore::record_with_connection(
            &transaction,
            &ReconciliationRecord {
                reconciliation_id: Uuid::new_v4(),
                task_id,
                step_number,
                actor_id: actor.id().to_string(),
                action: ReconciliationAction::RequeueForExecution,
                reason: reason.to_string(),
                evidence: "task re-queued after reconciliation; the recorded attempt is \
                           preserved and was not interpreted as a failure"
                    .to_string(),
                prior_status: TaskState::Blocked.to_string(),
                new_status: TaskState::Ready.to_string(),
                created_at: now.to_rfc3339(),
                invocation_id: None,
                verdict: "Requeue".to_string(),
                evidence_kind: "TaskState".to_string(),
                evidence_source: "operator decision".to_string(),
                evidence_json: "{}".to_string(),
                actor_kind: actor.kind().as_str().to_string(),
                auth_method: actor.method().as_str().to_string(),
                grant_id: Some(grant.grant_id),
            },
        )?;

        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            EVENT_TASK_REQUEUED,
            serde_json::json!({
                "task_id": task_id,
                "actor_id": actor.id(),
                "actor_kind": actor.kind().as_str(),
                "auth_method": actor.method().as_str(),
                "grant_id": grant.grant_id,
                "reason": reason,
                "from": TaskState::Blocked.to_string(),
                "to": TaskState::Ready.to_string(),
            }),
        )?;

        transaction.commit()?;
        Ok(())
    }

    // ── Authorization gate for resumed execution ──────────────────────────────

    /// What this task still owes the recovery process.
    pub fn obligations(&self, task_id: Uuid) -> Result<TaskRecoveryObligations, RecoveryError> {
        let retry_ready = self
            .checkpoint_store
            .list_retry_ready()?
            .into_iter()
            .filter(|checkpoint| checkpoint.task_id == task_id)
            .collect();

        Ok(TaskRecoveryObligations {
            retry_ready,
            outcome_unknown: self.checkpoint_store.list_outcome_unknown(task_id)?,
        })
    }

    /// Re-authorize a `RetryReady` step and mint the permit required to
    /// dispatch it again.
    ///
    /// This is the only sanctioned bridge between "retryable" and "executable".
    pub fn prepare_retry(
        &self,
        task_id: Uuid,
        step_number: usize,
        agent_id: &str,
    ) -> Result<RetryPermit, RecoveryError> {
        let authorization =
            self.authorizer()
                .reauthorize_recovery_task(task_id, step_number, agent_id)?;

        let checkpoint = self.checkpoint_store.get(task_id, step_number)?.ok_or(
            RecoveryError::CheckpointNotFound {
                task_id,
                step_number,
            },
        )?;

        let invocation_id =
            checkpoint
                .invocation_id
                .ok_or(RecoveryError::IncompleteCheckpoint {
                    task_id,
                    step_number,
                })?;
        let idempotency_key =
            checkpoint
                .idempotency_key
                .clone()
                .ok_or(RecoveryError::IncompleteCheckpoint {
                    task_id,
                    step_number,
                })?;
        let argument_fingerprint =
            checkpoint
                .argument_fingerprint
                .clone()
                .ok_or(RecoveryError::IncompleteCheckpoint {
                    task_id,
                    step_number,
                })?;

        Ok(RetryPermit {
            task_id,
            step_number,
            invocation_id,
            idempotency_key,
            argument_fingerprint,
            grant: authorization.grant,
            policy_id: authorization.policy_id,
            policy_version: authorization.policy_version,
            issued_at: authorization.decided_at,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn transition_task_if_running(
        &self,
        connection: &rusqlite::Connection,
        task_id: Uuid,
        target: TaskState,
    ) -> Result<(), RecoveryError> {
        let Some(task) = self.task_store.get_task(&task_id)? else {
            return Ok(());
        };
        if task.state == TaskState::Running {
            self.task_store.transition_state_with_connection(
                connection,
                task_id,
                TaskState::Running,
                target,
            )?;
        }
        Ok(())
    }

    fn emit_recovery_event_with_connection(
        &self,
        connection: &rusqlite::Connection,
        cp: &TaskCheckpoint,
        detail: &str,
    ) -> Result<(), RecoveryError> {
        self.event_bus.emit_event_with_connection(
            connection,
            Some(&cp.task_id.to_string()),
            EVENT_INVOCATION_RECOVERED,
            serde_json::json!({
                "task_id": cp.task_id,
                "step_number": cp.step_number,
                "invocation_id": cp.invocation_id,
                "semantics": cp.semantics.as_str(),
                "prior_status": cp.status.as_str(),
                "detail": detail,
            }),
        )?;
        Ok(())
    }
}
