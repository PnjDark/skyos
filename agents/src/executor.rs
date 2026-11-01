use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;

use kernel::artifacts::registry::ArtifactRegistry;
use kernel::delegation::CancellationStore;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::AuthorizationPolicy;
use kernel::recovery::{AuthorizationContext, AuthorizationStore, RetryPermit};
use kernel::tasks::checkpoint::{
    CheckpointInvocation, CheckpointStatus, CheckpointStore, IdempotencyLookup,
    compute_argument_fingerprint, compute_idempotency_key,
};
use kernel::tasks::store::TaskStore;
use models::provider::{ActionProposal, ModelProvider, StepHistory};
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolStatus};

use crate::types::{AgentBudget, AgentLoopStatus, AgentStepRecord, ExecutionSummary, StepOutcome};

// ── Executor ──────────────────────────────────────────────────────────────────

/// The single-agent runtime loop.
///
/// # Execution contract
///
/// 1. **Inspect**  – Resolve task, verify an active grant exists, collect schemas.
/// 2. **Plan**     – Ask the `ModelProvider` for the next `ActionProposal`.
/// 3. **Authorize & Act** – Confirm the grant is still valid; dispatch via
///    `UnifiedToolRegistry`.  If the grant is missing or expired the loop
///    **fails closed** immediately.
/// 4. **Observe**  – Collect the `ToolResult` and build a `StepHistory` entry.
/// 5. **Validate** – Check `ToolStatus`; promote `repair_count` on failure.
/// 6. **Repair or Complete** – If the model sets `is_complete` the loop exits
///    `Completed`.  If repairs are exhausted the loop exits `BudgetExhausted`.
///
/// # Invariants
///
/// - Every tool call goes through `UnifiedToolRegistry::dispatch`; no direct
///   tool access is permitted.
/// - The grant is re-checked before every dispatch (not just at startup), and
///   the capabilities it carries must still be permitted by the live policy.
/// - Budget limits (steps, wall time, repairs) are enforced before each cycle.
/// - An `AgentStepRecord` is appended for every cycle including failed ones.
/// - **A task with an unresolved recovery obligation never runs implicitly.**
///   `OutcomeUnknown` steps must be reconciled, and a `RetryReady` step may
///   only be re-dispatched under a `RetryPermit` issued by the recovery
///   authorizer (Phase 5.2).
pub struct ExecutorAgent {
    agent_id: String,
    task_store: TaskStore,
    grant_issuer: GrantIssuer,
    event_bus: EventBus,
    checkpoint_store: CheckpointStore,
    cancellation: CancellationStore,
    policy: Arc<AuthorizationPolicy>,
    resume_permit: Option<RetryPermit>,
    model: Arc<dyn ModelProvider>,
    workspace_root: PathBuf,
    budget: AgentBudget,
}

pub struct ExecutorServices {
    pub task_store: TaskStore,
    pub grant_issuer: GrantIssuer,
    pub event_bus: EventBus,
    pub checkpoint_store: CheckpointStore,
    /// Executions and their cancellation acknowledgements. The loop registers
    /// itself here so a cancellation can be attributed to this exact run.
    pub cancellation: CancellationStore,
    /// Policy in force for this runtime.  Persisted with each invocation's
    /// authorization context and re-checked before every dispatch.
    pub policy: Arc<AuthorizationPolicy>,
    /// Proof that a `RetryReady` step was re-authorized.  Without it, a task
    /// carrying a retryable checkpoint fails closed instead of resuming.
    pub resume_permit: Option<RetryPermit>,
}

impl ExecutorAgent {
    pub fn new(
        agent_id: impl Into<String>,
        services: ExecutorServices,
        model: Arc<dyn ModelProvider>,
        workspace_root: impl AsRef<Path>,
        budget: AgentBudget,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            task_store: services.task_store,
            grant_issuer: services.grant_issuer,
            event_bus: services.event_bus,
            checkpoint_store: services.checkpoint_store,
            cancellation: services.cancellation,
            policy: services.policy,
            resume_permit: services.resume_permit,
            model,
            workspace_root: workspace_root.as_ref().to_path_buf(),
            budget,
        }
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /// Run the bounded execution loop for `task_id`.
    ///
    /// Returns an [`ExecutionSummary`] regardless of how the loop terminates
    /// (normal completion, budget exhaustion, permission denial, or internal
    /// error).  The caller must inspect `summary.status` to determine outcome.
    pub async fn run(
        &self,
        task_id: Uuid,
        artifact_registry: &mut ArtifactRegistry,
    ) -> ExecutionSummary {
        let started_at = Utc::now();
        let wall_start = Instant::now();
        let max_wall = std::time::Duration::from_secs(self.budget.max_wall_seconds);

        // Register this cooperative loop. Any earlier loop for the same task is
        // marked superseded, so an old acknowledgement can never be read as
        // proof that *this* execution stopped.
        let execution_id = match self.cancellation.begin_execution(task_id, &self.agent_id) {
            Ok(execution_id) => execution_id,
            Err(error) => {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!("Failed to register execution: {error}"),
                    },
                    Vec::new(),
                    0,
                    started_at,
                );
            }
        };
        let _execution_guard = ExecutionGuard {
            store: self.cancellation.clone(),
            execution_id,
        };

        let schemas = UnifiedToolRegistry::export_schemas();

        let mut step_records: Vec<AgentStepRecord> = Vec::new();
        let mut history: Vec<StepHistory> = Vec::new();
        let mut step_index: usize = 0;
        let mut repair_attempts: usize = 0;

        // ── Phase 1: Inspect ──────────────────────────────────────────────────

        let task = match self.task_store.get_task(&task_id) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!("Task {task_id} not found in store"),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }
            Err(e) => {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!("TaskStore error: {e}"),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }
        };

        // ── Phase 5.2 gate: an interrupted task never resumes implicitly ──────
        let mut resume_permit = self.resume_permit.clone();
        if let Err(reason) = self.preflight_resume(task_id, resume_permit.as_ref()) {
            warn!(task_id = %task_id, reason = %reason, "Refusing to resume task");
            return self.terminal_summary(
                task_id,
                AgentLoopStatus::ResumeRejected { reason },
                step_records,
                repair_attempts,
                started_at,
            );
        }

        let checkpoint_step = match &resume_permit {
            // A resumed retry re-uses the exact step it was authorized for; it
            // never advances past an unresolved attempt.
            Some(permit) => permit.step_number,
            None => match self.checkpoint_store.list_for_task(task_id) {
                Ok(checkpoints) => checkpoints
                    .iter()
                    .map(|checkpoint| checkpoint.step_number)
                    .max()
                    .map(|step| step + 1)
                    .unwrap_or(0),
                Err(error) => {
                    return self.terminal_summary(
                        task_id,
                        AgentLoopStatus::InternalError {
                            message: format!("Failed to determine checkpoint step: {error}"),
                        },
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
            },
        };
        let mut checkpoint_step = checkpoint_step;

        info!(task_id = %task_id, title = %task.title, "ExecutorAgent: loop starting");

        // ── Main execution loop ───────────────────────────────────────────────

        loop {
            // ── Cancellation check: before starting a new cycle ──────────────
            if self.cancellation_pending(task_id) {
                return self.cancel_and_stop(
                    task_id,
                    execution_id,
                    checkpoint_step,
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // Budget: step count
            if step_index >= self.budget.max_steps {
                warn!(task_id = %task_id, steps = step_index, "Budget exhausted: max steps reached");
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::BudgetExhausted {
                        reason: format!("max_steps ({}) reached", self.budget.max_steps),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // Budget: wall time
            if wall_start.elapsed() >= max_wall {
                warn!(task_id = %task_id, elapsed = ?wall_start.elapsed(), "Budget exhausted: wall time reached");
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::BudgetExhausted {
                        reason: format!(
                            "max_wall_seconds ({}) reached",
                            self.budget.max_wall_seconds
                        ),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // ── Phase 3 pre-check: Authorize ──────────────────────────────────
            // Re-resolve the grant on every cycle so expiry or revocation is
            // caught immediately rather than mid-flight.  A resumed step uses
            // the narrowly scoped grant minted by the recovery authorizer.
            let grant = match resume_permit.as_ref() {
                Some(permit) => permit.grant.clone(),
                None => match self
                    .grant_issuer
                    .get_active_grant_for_agent_task(&self.agent_id, &task_id)
                {
                    Some(g) => g,
                    None => {
                        warn!(task_id = %task_id, "No active grant – loop failing closed");
                        return self.terminal_summary(
                            task_id,
                            AgentLoopStatus::PermissionDenied,
                            step_records,
                            repair_attempts,
                            started_at,
                        );
                    }
                },
            };

            // A grant is evidence that authorization once happened, not that it
            // still holds: the policy in force is re-checked every cycle.
            if !self
                .policy
                .authorize(&self.agent_id, &grant.capabilities)
                .is_granted()
            {
                warn!(
                    task_id = %task_id,
                    grant_id = %grant.grant_id,
                    "Active policy no longer permits this grant – failing closed"
                );
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::PermissionDenied,
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // ── Phase 2: Plan ─────────────────────────────────────────────────
            let proposal: ActionProposal = match timeout(
                std::time::Duration::from_secs(60),
                self.model.propose_action(&task.title, &schemas, &history),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    warn!(task_id = %task_id, error = %e, "ModelProvider error");
                    return self.terminal_summary(
                        task_id,
                        AgentLoopStatus::InternalError {
                            message: format!("ModelProvider error: {e}"),
                        },
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
                Err(_) => {
                    warn!(task_id = %task_id, "ModelProvider timed out (60s)");
                    return self.terminal_summary(
                        task_id,
                        AgentLoopStatus::InternalError {
                            message: "ModelProvider timed out".into(),
                        },
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
            };

            // Completion signal
            if proposal.is_complete {
                // ── Cancellation check: before committing the final result ───
                if self.cancellation_pending(task_id) {
                    return self.cancel_and_stop(
                        task_id,
                        execution_id,
                        checkpoint_step,
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
                if resume_permit.is_some() {
                    return self.terminal_summary(
                        task_id,
                        AgentLoopStatus::ResumeRejected {
                            reason: "the model declared completion while a retry-ready \
                                     checkpoint is still unresolved"
                                .to_string(),
                        },
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
                info!(task_id = %task_id, steps = step_index, "Model declared task complete");
                step_records.push(AgentStepRecord {
                    step_index,
                    correlation_id: Uuid::new_v4(),
                    tool_id: proposal.tool_id.clone(),
                    operation_id: proposal.operation_id.clone(),
                    outcome: StepOutcome::Completed,
                    output_snippet: None,
                    error_message: None,
                    started_at: Utc::now(),
                    finished_at: Utc::now(),
                });
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::Completed,
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // ── Phase 3: Act ──────────────────────────────────────────────────
            // ── Cancellation check: before dispatching another invocation ────
            // Nothing has been dispatched for this step yet, so stopping here
            // leaves no side effect to reconcile.
            if self.cancellation_pending(task_id) {
                return self.cancel_and_stop(
                    task_id,
                    execution_id,
                    checkpoint_step,
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // A resumed step keeps the invocation identity recorded before the
            // crash so that the retry is provably the same operation.
            let active_resume = resume_permit.take();
            let ctx = match active_resume.as_ref() {
                Some(permit) => ToolContext::with_invocation_id(
                    task_id,
                    self.agent_id.clone(),
                    permit.invocation_id,
                ),
                None => ToolContext::new(task_id, self.agent_id.clone()),
            };
            let correlation_id = ctx.invocation_id;
            let step_started = Utc::now();
            let semantics = UnifiedToolRegistry::side_effect_semantics(
                &proposal.tool_id,
                &proposal.operation_id,
            );

            let argument_fingerprint = compute_argument_fingerprint(&proposal.parameters);
            let computed_key = compute_idempotency_key(
                &task_id,
                checkpoint_step,
                &proposal.tool_id,
                &proposal.operation_id,
                &proposal.parameters,
            );

            // Reusing an authorized retry slot with different inputs is a
            // conflict, not a replay: the recorded attempt stays unresolved and
            // the new intent may not silently replace it.
            let idempotency_key = match active_resume.as_ref() {
                Some(permit) => {
                    if permit.argument_fingerprint != argument_fingerprint {
                        return self.terminal_summary(
                            task_id,
                            AgentLoopStatus::ResumeRejected {
                                reason: format!(
                                    "the model proposed different arguments than the authorized \
                                     retry of step {}; the recorded attempt must be reconciled \
                                     instead of silently replaced",
                                    permit.step_number
                                ),
                            },
                            step_records,
                            repair_attempts,
                            started_at,
                        );
                    }
                    if permit.idempotency_key != computed_key {
                        return self.terminal_summary(
                            task_id,
                            AgentLoopStatus::ResumeRejected {
                                reason: "the recorded idempotency key does not match the \
                                         authorized retry's argument fingerprint"
                                    .to_string(),
                            },
                            step_records,
                            repair_attempts,
                            started_at,
                        );
                    }
                    permit.idempotency_key.clone()
                }
                None => computed_key,
            };

            let request = InvocationRequest {
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                parameters: proposal.parameters.clone(),
                idempotency_key: Some(idempotency_key.clone()),
            };

            let pending_checkpoint = match active_resume.as_ref() {
                // The row already exists in `RetryReady`; re-verify that the
                // ledger still agrees with the permit before re-dispatching.
                Some(permit) => (|| -> anyhow::Result<()> {
                    let mut connection = self.checkpoint_store.connection()?;
                    let transaction = connection.transaction()?;
                    match CheckpointStore::lookup_idempotency(
                        &transaction,
                        &permit.idempotency_key,
                        &permit.argument_fingerprint,
                    )? {
                        IdempotencyLookup::InFlight(recorded)
                            if recorded.task_id == task_id
                                && recorded.step_number == permit.step_number
                                && recorded.status == CheckpointStatus::RetryReady => {}
                        other => anyhow::bail!(
                            "resume blocked: the ledger no longer holds a retry-ready row for \
                             this invocation ({other:?})"
                        ),
                    }
                    self.event_bus.emit_event_with_connection(
                        &transaction,
                        Some(&task_id.to_string()),
                        "ToolInvocationReDispatched",
                        serde_json::json!({
                            "invocation_id": correlation_id,
                            "idempotency_key": &idempotency_key,
                            "step_number": checkpoint_step,
                            "authorized_at": permit.issued_at,
                            "policy_id": &permit.policy_id,
                            "policy_version": permit.policy_version,
                        }),
                    )?;
                    transaction.commit()?;
                    Ok(())
                })(),
                None => (|| -> anyhow::Result<()> {
                    let mut connection = self.checkpoint_store.connection()?;
                    let transaction = connection.transaction()?;
                    CheckpointStore::write_pending_invocation(
                        &transaction,
                        task_id,
                        &self.agent_id,
                        checkpoint_step,
                        &CheckpointInvocation {
                            invocation_id: correlation_id,
                            idempotency_key: idempotency_key.clone(),
                            argument_fingerprint: argument_fingerprint.clone(),
                            semantics: semantics.clone(),
                            tool_id: proposal.tool_id.clone(),
                            operation_id: proposal.operation_id.clone(),
                        },
                    )?;
                    // The capability intent is durable before the dispatch, in
                    // the same transaction as the checkpoint.  The required
                    // capability family is derived by the runtime from the tool
                    // manifest — the agent never declares its own authority.
                    AuthorizationStore::record_with_connection(
                        &transaction,
                        &AuthorizationContext {
                            task_id,
                            step_number: checkpoint_step,
                            agent_id: self.agent_id.clone(),
                            capabilities: grant.capabilities.clone(),
                            required_capability: UnifiedToolRegistry::required_capability_kind(
                                &proposal.tool_id,
                                &proposal.operation_id,
                            ),
                            policy_id: self.policy.policy_id().to_string(),
                            policy_version: self.policy.version(),
                            recorded_at: Utc::now().to_rfc3339(),
                        },
                    )?;
                    self.event_bus.emit_event_with_connection(
                        &transaction,
                        Some(&task_id.to_string()),
                        "ToolInvocationPending",
                        serde_json::json!({
                            "invocation_id": correlation_id,
                            "idempotency_key": &idempotency_key,
                            "argument_fingerprint": &argument_fingerprint,
                            "step_number": checkpoint_step,
                            "tool_id": &proposal.tool_id,
                            "operation_id": &proposal.operation_id,
                            "semantics": semantics.as_str(),
                        }),
                    )?;
                    transaction.commit()?;
                    Ok(())
                })(),
            };
            if let Err(error) = pending_checkpoint {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!("Failed to persist pending invocation: {error:#}"),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            let dispatched_checkpoint = (|| -> anyhow::Result<()> {
                let mut connection = self.checkpoint_store.connection()?;
                let transaction = connection.transaction()?;
                CheckpointStore::mark_dispatched(
                    &transaction,
                    task_id,
                    checkpoint_step,
                    correlation_id,
                    &idempotency_key,
                    &proposal.tool_id,
                    &proposal.operation_id,
                )?;
                self.event_bus.emit_event_with_connection(
                    &transaction,
                    Some(&task_id.to_string()),
                    "ToolInvocationDispatched",
                    serde_json::json!({
                        "invocation_id": correlation_id,
                        "idempotency_key": &idempotency_key,
                        "step_number": checkpoint_step,
                    }),
                )?;
                transaction.commit()?;
                Ok(())
            })();
            if let Err(error) = dispatched_checkpoint {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!("Failed to persist dispatched invocation: {error:#}"),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            debug!(
                task_id = %task_id,
                step = step_index,
                tool_id = %request.tool_id,
                op = %request.operation_id,
                "Dispatching"
            );

            let mut registry =
                UnifiedToolRegistry::new(&self.event_bus, artifact_registry, &self.grant_issuer);

            let tool_result = registry
                .dispatch(&ctx, &grant, request, &self.workspace_root)
                .await;

            let step_finished = Utc::now();
            let invocation_matches = tool_result.invocation_id == correlation_id;

            // ── Phase 4: Observe ──────────────────────────────────────────────
            let output_snippet = match &tool_result.output {
                tools::types::ToolOutput::Text(s) => Some(s.chars().take(512).collect()),
                tools::types::ToolOutput::ProcessResult { stdout, .. } => {
                    Some(stdout.chars().take(512).collect())
                }
                _ => None,
            };

            let mut error_snippet = tool_result
                .error_message
                .as_deref()
                .map(|e| e.chars().take(256).collect::<String>());

            // ── Phase 5: Validate ─────────────────────────────────────────────
            let outcome_unknown = !invocation_matches
                || matches!(
                    tool_result.status,
                    ToolStatus::TimedOut
                        | ToolStatus::OutcomeUnknown
                        | ToolStatus::AuditPersistenceFailed
                );
            if !invocation_matches {
                error_snippet = Some(format!(
                    "Dispatcher returned invocation {} for expected invocation {}",
                    tool_result.invocation_id, correlation_id
                ));
            }
            let (outcome, step_error) = if outcome_unknown {
                (StepOutcome::OutcomeUnknown, error_snippet.clone())
            } else {
                match tool_result.status {
                    ToolStatus::Succeeded => (StepOutcome::Succeeded, None),
                    ToolStatus::PermissionDenied => {
                        warn!(task_id = %task_id, step = step_index, "Permission denied by policy engine");
                        (StepOutcome::PermissionDenied, error_snippet.clone())
                    }
                    ToolStatus::Failed => (StepOutcome::ToolFailed, error_snippet.clone()),
                    ToolStatus::TimedOut
                    | ToolStatus::OutcomeUnknown
                    | ToolStatus::AuditPersistenceFailed => unreachable!(),
                }
            };

            let persisted_result = (|| -> anyhow::Result<()> {
                let mut connection = self.checkpoint_store.connection()?;
                let transaction = connection.transaction()?;
                if outcome_unknown {
                    CheckpointStore::mark_outcome_unknown(&transaction, task_id, checkpoint_step)?;
                } else if outcome == StepOutcome::Succeeded {
                    CheckpointStore::mark_succeeded(&transaction, task_id, checkpoint_step)?;
                } else {
                    CheckpointStore::mark_failed(&transaction, task_id, checkpoint_step)?;
                }
                let status_name = if outcome_unknown {
                    "OutcomeUnknown"
                } else {
                    match tool_result.status {
                        ToolStatus::Succeeded => "Succeeded",
                        ToolStatus::Failed => "Failed",
                        ToolStatus::PermissionDenied => "PermissionDenied",
                        ToolStatus::TimedOut
                        | ToolStatus::OutcomeUnknown
                        | ToolStatus::AuditPersistenceFailed => "OutcomeUnknown",
                    }
                };
                self.event_bus.emit_event_with_connection(
                    &transaction,
                    Some(&task_id.to_string()),
                    "AgentStepCompleted",
                    serde_json::json!({
                        "step_index": step_index,
                        "step_number": checkpoint_step,
                        "correlation_id": correlation_id,
                        "tool_id": &proposal.tool_id,
                        "operation_id": &proposal.operation_id,
                        "status": status_name,
                        "output": &output_snippet,
                        "error": &step_error,
                        "artifact_id": tool_result.artifact.as_ref().map(|artifact| &artifact.artifact_id),
                    }),
                )?;
                transaction.commit()?;
                Ok(())
            })();
            if let Err(error) = persisted_result {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::InternalError {
                        message: format!(
                            "Tool invocation outcome could not be durably recorded; checkpoint remains unresolved: {error:#}"
                        ),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            // The recovery grant authorized exactly this one retry.  Once the
            // retry has an outcome it must not linger as ambient authority for
            // later steps of the same task.
            if let Some(permit) = active_resume.as_ref()
                && let Err(error) = self.grant_issuer.revoke_grant(&permit.grant.grant_id)
            {
                debug!(
                    task_id = %task_id,
                    grant_id = %permit.grant.grant_id,
                    %error,
                    "Recovery grant was already inactive"
                );
            }

            // Build the history entry for the model's next cycle
            history.push(StepHistory {
                step_number: step_index,
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                status: format!("{:?}", tool_result.status),
                output_snippet: output_snippet.clone(),
                error_message: step_error.clone(),
            });

            step_records.push(AgentStepRecord {
                step_index,
                correlation_id,
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                outcome: outcome.clone(),
                output_snippet,
                error_message: step_error.clone(),
                started_at: step_started,
                finished_at: step_finished,
            });

            // ── Phase 6: Repair or Continue ───────────────────────────────────
            if outcome == StepOutcome::PermissionDenied {
                // Hard stop – permission denial is never repaired.
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::PermissionDenied,
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            if outcome == StepOutcome::OutcomeUnknown {
                return self.terminal_summary(
                    task_id,
                    AgentLoopStatus::OutcomeUnknown {
                        reason: step_error.unwrap_or_else(|| {
                            "Tool outcome or completion audit requires reconciliation".to_string()
                        }),
                    },
                    step_records,
                    repair_attempts,
                    started_at,
                );
            }

            if outcome == StepOutcome::ToolFailed {
                repair_attempts += 1;
                warn!(
                    task_id = %task_id,
                    repair = repair_attempts,
                    max = self.budget.max_repair_attempts,
                    "Step failed – counting repair attempt"
                );
                if repair_attempts > self.budget.max_repair_attempts {
                    return self.terminal_summary(
                        task_id,
                        AgentLoopStatus::BudgetExhausted {
                            reason: format!(
                                "max_repair_attempts ({}) exceeded",
                                self.budget.max_repair_attempts
                            ),
                        },
                        step_records,
                        repair_attempts,
                        started_at,
                    );
                }
                // History already includes the failed step; the model will see
                // the error and should propose a corrected action next cycle.
            }

            step_index += 1;
            checkpoint_step += 1;
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Decide whether this task may run at all.
    ///
    /// Two obligations can exist after a crash:
    ///
    /// - `OutcomeUnknown` — the external world may already contain the effect.
    ///   Nothing may run until it is reconciled.
    /// - `RetryReady` — the operation is semantically safe to retry, but that is
    ///   a *retryability* verdict, not an authorization.  A `RetryPermit` from
    ///   the recovery authorizer is required, and it must bind to the exact
    ///   invocation that was interrupted.
    fn preflight_resume(&self, task_id: Uuid, permit: Option<&RetryPermit>) -> Result<(), String> {
        let outcome_unknown = self
            .checkpoint_store
            .list_outcome_unknown(task_id)
            .map_err(|error| format!("Failed to inspect the checkpoint ledger: {error}"))?;

        if !outcome_unknown.is_empty() {
            let steps = outcome_unknown
                .iter()
                .map(|checkpoint| checkpoint.step_number.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "checkpoint step(s) {steps} have an unknown external outcome; \
                 they must be reconciled before this task may run again"
            ));
        }

        let retry_ready: Vec<_> = self
            .checkpoint_store
            .list_retry_ready()
            .map_err(|error| format!("Failed to inspect retry-ready checkpoints: {error}"))?
            .into_iter()
            .filter(|checkpoint| checkpoint.task_id == task_id)
            .collect();

        if retry_ready.is_empty() {
            if permit.is_some() {
                return Err(
                    "a resume permit was supplied but the task has no retry-ready checkpoint"
                        .to_string(),
                );
            }
            return Ok(());
        }

        if retry_ready.len() > 1 {
            return Err(format!(
                "{} checkpoints are retry-ready; exactly one step may be resumed per run",
                retry_ready.len()
            ));
        }

        let checkpoint = &retry_ready[0];
        let Some(permit) = permit else {
            return Err(format!(
                "step {} is retry-ready but automatic resumption is disabled until a \
                 recovery authorization permit is supplied",
                checkpoint.step_number
            ));
        };

        if permit.task_id != task_id {
            return Err(format!(
                "resume permit is for task {}, not {task_id}",
                permit.task_id
            ));
        }
        if permit.step_number != checkpoint.step_number {
            return Err(format!(
                "resume permit authorizes step {} but the ledger is waiting on step {}",
                permit.step_number, checkpoint.step_number
            ));
        }
        if Some(permit.invocation_id) != checkpoint.invocation_id {
            return Err(
                "resume permit does not match the recorded invocation identity".to_string(),
            );
        }
        if Some(permit.idempotency_key.as_str()) != checkpoint.idempotency_key.as_deref() {
            return Err("resume permit does not match the recorded idempotency key".to_string());
        }
        if Some(permit.argument_fingerprint.as_str()) != checkpoint.argument_fingerprint.as_deref()
        {
            return Err(
                "resume permit does not match the recorded argument fingerprint".to_string(),
            );
        }
        if !permit.grant.is_valid() {
            return Err("the recovery grant has expired or been revoked".to_string());
        }
        if permit.grant.task_id != task_id {
            return Err("the recovery grant is scoped to a different task".to_string());
        }
        if permit.grant.agent_id != self.agent_id {
            return Err(format!(
                "the recovery grant was issued to '{}', not '{}'",
                permit.grant.agent_id, self.agent_id
            ));
        }

        // The live policy must still permit what the permit authorizes.
        if !self
            .policy
            .authorize(&self.agent_id, &permit.grant.capabilities)
            .is_granted()
        {
            return Err(
                "the active policy no longer permits the capabilities of the recovery grant"
                    .to_string(),
            );
        }

        Ok(())
    }

    fn terminal_summary(
        &self,
        task_id: Uuid,
        status: AgentLoopStatus,
        step_records: Vec<AgentStepRecord>,
        repair_attempts: usize,
        started_at: chrono::DateTime<Utc>,
    ) -> ExecutionSummary {
        let steps_executed = step_records.len();
        ExecutionSummary {
            task_id,
            agent_id: self.agent_id.clone(),
            status,
            steps_executed,
            repair_attempts,
            step_records,
            started_at,
            finished_at: Utc::now(),
        }
    }
}
