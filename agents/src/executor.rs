use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;

use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
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
/// - The grant is re-checked before every dispatch (not just at startup).
/// - Budget limits (steps, wall time, repairs) are enforced before each cycle.
/// - An `AgentStepRecord` is appended for every cycle including failed ones.
pub struct ExecutorAgent {
    agent_id: String,
    task_store: TaskStore,
    grant_issuer: GrantIssuer,
    event_bus: EventBus,
    model: Arc<dyn ModelProvider>,
    workspace_root: PathBuf,
    budget: AgentBudget,
}

impl ExecutorAgent {
    pub fn new(
        agent_id: impl Into<String>,
        task_store: TaskStore,
        grant_issuer: GrantIssuer,
        event_bus: EventBus,
        model: Arc<dyn ModelProvider>,
        workspace_root: impl AsRef<Path>,
        budget: AgentBudget,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            task_store,
            grant_issuer,
            event_bus,
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

        info!(task_id = %task_id, title = %task.title, "ExecutorAgent: loop starting");

        // ── Main execution loop ───────────────────────────────────────────────

        loop {
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
            // caught immediately rather than mid-flight.
            let grant = match self.grant_issuer.get_active_grant_for_task(&task_id) {
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
            };

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
            let ctx = ToolContext::new(task_id, self.agent_id.clone());
            let correlation_id = ctx.invocation_id;
            let step_started = Utc::now();

            let request = InvocationRequest {
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                parameters: proposal.parameters.clone(),
                idempotency_key: Some(format!("step-{step_index}-{correlation_id}")),
            };

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

            // ── Phase 4: Observe ──────────────────────────────────────────────
            let output_snippet = match &tool_result.output {
                tools::types::ToolOutput::Text(s) => Some(s.chars().take(512).collect()),
                tools::types::ToolOutput::ProcessResult { stdout, .. } => {
                    Some(stdout.chars().take(512).collect())
                }
                _ => None,
            };

            let error_snippet = tool_result
                .error_message
                .as_deref()
                .map(|e| e.chars().take(256).collect::<String>());

            // ── Phase 5: Validate ─────────────────────────────────────────────
            let (outcome, step_error) = match tool_result.status {
                ToolStatus::Succeeded => (StepOutcome::Succeeded, None),
                ToolStatus::PermissionDenied => {
                    warn!(task_id = %task_id, step = step_index, "Permission denied by policy engine");
                    (StepOutcome::PermissionDenied, error_snippet.clone())
                }
                ToolStatus::Failed | ToolStatus::TimedOut => {
                    (StepOutcome::ToolFailed, error_snippet.clone())
                }
            };

            // Build the history entry for the model's next cycle
            history.push(StepHistory {
                step_number: step_index,
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                status: format!("{:?}", tool_result.status),
                output_snippet: output_snippet.clone(),
                error_message: step_error.clone(),
            });

            // Emit an event for this step's completion
            let _ = self.event_bus.emit_event(
                Some(&task_id.to_string()),
                "AgentStepCompleted",
                serde_json::json!({
                    "step_index": step_index,
                    "correlation_id": correlation_id,
                    "tool_id": &proposal.tool_id,
                    "operation_id": &proposal.operation_id,
                    "status": format!("{:?}", tool_result.status),
                }),
            );

            step_records.push(AgentStepRecord {
                step_index,
                correlation_id,
                tool_id: proposal.tool_id.clone(),
                operation_id: proposal.operation_id.clone(),
                outcome: outcome.clone(),
                output_snippet,
                error_message: step_error,
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
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

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
