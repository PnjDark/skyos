use anyhow::{Context, Result};
use kernel::events::EventBus;
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use serde_json::json;
use uuid::Uuid;

pub const EVENT_TASK_RECONCILED: &str = "TaskReconciledAfterInterruption";

pub struct RecoveryEngine<'a> {
    task_store: &'a TaskStore,
    event_bus: &'a EventBus,
}

impl<'a> RecoveryEngine<'a> {
    pub fn new(task_store: &'a TaskStore, event_bus: &'a EventBus) -> Self {
        Self {
            task_store,
            event_bus,
        }
    }

    /// Scans runtime ledger on startup and reconciles tasks left in `Running` state due to process crashes.
    /// Propagates all errors upward so main() fails closed if recovery fails.
    pub fn reconcile_orphaned_tasks(&self) -> Result<Vec<Uuid>> {
        let tasks = self.task_store.list_tasks()?;
        let mut reconciled = Vec::new();

        for task in tasks {
            if task.state == TaskState::Running {
                // 1. Transition state from Running -> Failed
                self.task_store
                    .transition_state(task.task_id, TaskState::Running, TaskState::Failed)
                    .with_context(|| {
                        format!("Failed to reconcile state for task {}", task.task_id)
                    })?;

                // 2. Emit mandatory reconciliation audit event (Must NOT be suppressed)
                self.event_bus
                    .emit_event(
                        Some(&task.task_id.to_string()),
                        EVENT_TASK_RECONCILED,
                        json!({
                            "task_id": task.task_id,
                            "previous_state": "Running",
                            "new_state": "Failed",
                            "reason": "Process was interrupted prior to task completion"
                        }),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to emit reconciliation event for task {}",
                            task.task_id
                        )
                    })?;

                reconciled.push(task.task_id);
            }
        }

        Ok(reconciled)
    }
}
