/// Phase 5 — Crash Recovery & Execution Semantics.
///
/// `RecoveryEngine` is the kernel-level component that classifies interrupted
/// invocations and applies the correct recovery strategy on restart.
///
/// # Recovery invariants
///
/// 1. **Re-evaluate capability grants** before any retry decision.
///    A grant that was valid before the crash may have expired or been
///    revoked.  Stale grants are never reused.
///
/// 2. **Never blindly retry `AtMostOnce` operations.**  If an interrupted
///    invocation cannot prove its side effect did not take effect, the step is
///    marked `Failed` and the agent must revise its plan.
///
/// 3. **Idempotent operations** are safe to re-dispatch with the same
///    parameters and idempotency key.
///
/// 4. **Reconcilable operations** require out-of-band physical-state
///    verification (e.g. `git log`, file-hash check) before a retry decision
///    is made.  The engine marks them `OutcomeUnknown` so the caller can
///    perform tool-specific reconciliation.
///
/// 5. **Recovery is itself idempotent** — repeated calls produce the same
///    classification without compounding side effects.
use std::path::Path;

use chrono::Utc;
use thiserror::Error;
use uuid::Uuid;

use crate::events::EventBus;
use crate::permissions::issuer::GrantIssuer;
use crate::tasks::checkpoint::{CheckpointError, CheckpointStatus, CheckpointStore, SideEffectSemantics, TaskCheckpoint};
use crate::tasks::state::TaskState;
use crate::tasks::store::{TaskStore, TaskStoreError};

// ── Public types ──────────────────────────────────────────────────────────────

/// How the recovery engine classified and handled an interrupted invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Grant was missing or expired; task transitioned to `Failed`.
    GrantExpired,
    /// Idempotent operation: cleared for re-dispatch on resume.
    ReadyForRetry,
    /// At-most-once operation: marked `Failed` in the ledger; agent must revise.
    MarkedFailed { reason: String },
    /// Reconcilable operation: marked `OutcomeUnknown`; caller must inspect
    /// physical state before deciding whether to retry.
    RequiresReconciliation,
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
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Kernel-level crash recovery coordinator.
pub struct RecoveryEngine {
    checkpoint_store: CheckpointStore,
    task_store: TaskStore,
    event_bus: EventBus,
    grant_issuer: GrantIssuer,
}

impl RecoveryEngine {
    pub fn new(
        checkpoint_store: CheckpointStore,
        task_store: TaskStore,
        event_bus: EventBus,
        grant_issuer: GrantIssuer,
    ) -> Self {
        Self {
            checkpoint_store,
            task_store,
            event_bus,
            grant_issuer,
        }
    }

    /// Convenience constructor: opens `CheckpointStore` from the same path as
    /// `TaskStore` (they share `runtime_state.db`).
    pub fn open(
        db_path: impl AsRef<Path>,
        task_store: TaskStore,
        event_bus: EventBus,
        grant_issuer: GrantIssuer,
    ) -> Result<Self, RecoveryError> {
        let checkpoint_store = CheckpointStore::open(db_path)?;
        Ok(Self::new(checkpoint_store, task_store, event_bus, grant_issuer))
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// On process startup, scan all `Pending` and `Dispatched` checkpoints
    /// and apply the correct recovery strategy for each.
    ///
    /// Returns one `RecoveryRecord` per affected checkpoint.
    pub fn recover_all(&self) -> Result<Vec<RecoveryRecord>, RecoveryError> {
        let unresolved = self.checkpoint_store.list_unresolved()?;
        let mut records = Vec::new();

        for checkpoint in unresolved {
            let record = self.recover_one(&checkpoint)?;
            records.push(record);
        }

        Ok(records)
    }

    // ── Private recovery logic ────────────────────────────────────────────────

    fn recover_one(&self, cp: &TaskCheckpoint) -> Result<RecoveryRecord, RecoveryError> {
        let recovered_at = Utc::now().to_rfc3339();

        // ── Invariant 1: re-evaluate grant ────────────────────────────────────
        // If no valid grant exists the task cannot safely resume regardless of
        // operation semantics.  Transition it to Failed and stop.
        let grant_valid = self
            .grant_issuer
            .get_active_grant_for_task(&cp.task_id)
            .map(|g| g.is_valid())
            .unwrap_or(false);

        if !grant_valid {
            self.fail_task_if_running(cp.task_id, "Grant expired or revoked before recovery")?;
            return Ok(RecoveryRecord {
                task_id: cp.task_id,
                step_number: cp.step_number,
                tool_id: cp.tool_id.clone(),
                operation_id: cp.operation_id.clone(),
                semantics: cp.semantics.clone(),
                prior_status: cp.status.clone(),
                decision: RecoveryDecision::GrantExpired,
                recovered_at,
            });
        }

        // ── Invariant 2–4: classify by semantics ──────────────────────────────
        let conn = self.checkpoint_store.pool.connection()?;
        let decision = match &cp.semantics {
            SideEffectSemantics::Idempotent => {
                // Reset to Pending so the executor loop can re-dispatch safely.
                CheckpointStore::write_pending(
                    &conn,
                    cp.task_id,
                    &cp.agent_id,
                    cp.step_number,
                    &SideEffectSemantics::Idempotent,
                )?;
                self.emit_recovery_event(cp, "Idempotent: reset to Pending for re-dispatch")?;
                RecoveryDecision::ReadyForRetry
            }

            SideEffectSemantics::AtMostOnce => {
                // Mark the step failed — do NOT retry; the agent must plan a
                // different action.
                CheckpointStore::mark_failed(&conn, cp.task_id, cp.step_number)?;
                let reason = format!(
                    "AtMostOnce operation '{}/{}' interrupted with unknown side effect; \
                     blind retry unsafe",
                    cp.tool_id.as_deref().unwrap_or("?"),
                    cp.operation_id.as_deref().unwrap_or("?")
                );
                self.emit_recovery_event(cp, &reason)?;
                RecoveryDecision::MarkedFailed {
                    reason: reason.clone(),
                }
            }

            SideEffectSemantics::Reconcilable => {
                // Mark as OutcomeUnknown; caller must do tool-specific read-back
                // (e.g. `git log --oneline -1`, file-hash check) before retry.
                CheckpointStore::mark_outcome_unknown(&conn, cp.task_id, cp.step_number)?;
                self.emit_recovery_event(
                    cp,
                    "Reconcilable: marked OutcomeUnknown; physical reconciliation required",
                )?;
                RecoveryDecision::RequiresReconciliation
            }
        };

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

    fn fail_task_if_running(&self, task_id: Uuid, reason: &str) -> Result<(), RecoveryError> {
        // Guard: only transition if the task is still Running (idempotent).
        let task = match self.task_store.get_task(&task_id)? {
            Some(t) => t,
            None => return Ok(()),
        };
        if task.state == TaskState::Running {
            self.task_store
                .transition_state(task_id, TaskState::Running, TaskState::Failed)?;
        }
        let _ = self.event_bus.emit_event(
            Some(&task_id.to_string()),
            "TaskRecoveredGrantExpired",
            serde_json::json!({ "task_id": task_id, "reason": reason }),
        );
        Ok(())
    }

    fn emit_recovery_event(&self, cp: &TaskCheckpoint, detail: &str) -> Result<(), RecoveryError> {
        let _ = self.event_bus.emit_event(
            Some(&cp.task_id.to_string()),
            "InvocationRecovered",
            serde_json::json!({
                "task_id": cp.task_id,
                "step_number": cp.step_number,
                "invocation_id": cp.invocation_id,
                "semantics": cp.semantics.as_str(),
                "prior_status": cp.status.as_str(),
                "detail": detail,
            }),
        );
        Ok(())
    }
}
