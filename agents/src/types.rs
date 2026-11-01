use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Budget ────────────────────────────────────────────────────────────────────

/// Hard execution limits enforced by the agent loop.
///
/// Every limit is a *maximum*; the loop terminates as soon as any one is
/// exceeded.  A value of `0` for numeric limits means "unlimited" only where
/// explicitly documented – otherwise treat `0` as an instant-halt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBudget {
    /// Maximum number of plan-act-observe cycles before forced termination.
    pub max_steps: usize,
    /// Maximum cumulative wall-clock seconds for the whole loop.
    pub max_wall_seconds: u64,
    /// Maximum consecutive repair attempts before the loop gives up.
    pub max_repair_attempts: usize,
}

impl Default for AgentBudget {
    fn default() -> Self {
        Self {
            max_steps: 30,
            max_wall_seconds: 300, // 5 minutes
            max_repair_attempts: 3,
        }
    }
}

// ── Per-step record ───────────────────────────────────────────────────────────

/// Disposition of one executed step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepOutcome {
    /// Tool executed and returned a success status.
    Succeeded,
    /// Tool executed but returned a non-success status.
    ToolFailed,
    /// The runtime refused to dispatch (grant missing, expired, or revoked).
    PermissionDenied,
    /// Physical outcome or its audit evidence could not be established.
    OutcomeUnknown,
    /// Model signalled task completion (no tool call needed).
    Completed,
    /// Model or tool raised an error; repair was triggered.
    Repaired,
}

/// Immutable record written after every step completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStepRecord {
    pub step_index: usize,
    pub correlation_id: Uuid,
    pub tool_id: String,
    pub operation_id: String,
    pub outcome: StepOutcome,
    pub output_snippet: Option<String>,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

// ── Loop status ───────────────────────────────────────────────────────────────

/// Terminal reason the execution loop stopped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentLoopStatus {
    /// Model declared the task complete.
    Completed,
    /// Budget (steps / time / repairs) was exhausted before completion.
    BudgetExhausted { reason: String },
    /// Grant was missing, expired, or revoked; loop failed closed.
    PermissionDenied,
    /// A dispatched operation may have taken effect but requires reconciliation.
    OutcomeUnknown { reason: String },
    /// The task was cancelled while this loop was running. The loop observed
    /// `Cancelling`, wrote a durable acknowledgement, and stopped without
    /// starting another operation.
    Cancelled,
    /// An interrupted task refused to resume because its recovery obligations
    /// were not satisfied (unreconciled outcome, missing or mismatched
    /// authorization permit, or a proposal that diverges from the authorized
    /// retry).  Nothing was dispatched.
    ResumeRejected { reason: String },
    /// Unrecoverable internal error (e.g. model provider failure).
    InternalError { message: String },
}

// ── Execution summary ─────────────────────────────────────────────────────────

/// Full, structured result returned to the caller after the loop terminates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub task_id: Uuid,
    pub agent_id: String,
    pub status: AgentLoopStatus,
    pub steps_executed: usize,
    pub repair_attempts: usize,
    pub step_records: Vec<AgentStepRecord>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}
