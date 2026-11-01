//! Phase 6.1A/6.1B — durable delegation primitives.
//!
//! This module owns exactly two things:
//!
//! * the parent-child relationship and its dependency edges, persisted in the
//!   same SQLite WAL as every other task fact;
//! * the transactional `Created → Ready` readiness gate, so a dependent task
//!   cannot be released before its prerequisites complete.
//!
//! It deliberately does **not** introduce a scheduler, a bus, or a second task
//! engine: it composes `TaskStore`, `EventBus`, and the existing `tasks` table.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod budget;
pub mod cancellation;
pub mod store;

pub use budget::{
    BudgetError, BudgetKernel, ElapsedSource, EntryKind, Envelope, Exposure, LedgerEntry,
    RecoveryBound,
};
pub use cancellation::{
    Acknowledgement, CancellationCoordinator, CancellationError, CancellationIntent,
    CancellationStore, CascadeProgress, EscalationResolution, ExecutionRecord, IntentStatus,
};
pub use store::DelegationKernel;

/// One edge in the dependency DAG: `dependent` may not run until `prerequisite`
/// is `Completed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDependency {
    pub dependent_task_id: Uuid,
    pub prerequisite_task_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Instructions for creating a delegated child task.
#[derive(Debug, Clone)]
pub struct ChildTaskSpec {
    pub title: String,
    pub objective: String,
    pub assigned_agent_id: Option<String>,
    pub dependencies: Vec<Uuid>,
}

impl ChildTaskSpec {
    pub fn new(title: impl Into<String>, objective: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            objective: objective.into(),
            assigned_agent_id: None,
            dependencies: Vec::new(),
        }
    }

    pub fn assigned_to(mut self, agent_id: impl Into<String>) -> Self {
        self.assigned_agent_id = Some(agent_id.into());
        self
    }

    pub fn depends_on(mut self, prerequisite: Uuid) -> Self {
        self.dependencies.push(prerequisite);
        self
    }
}

#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("task store error: {0}")]
    TaskStore(#[from] crate::tasks::store::TaskStoreError),
    #[error("database error: {0}")]
    Database(#[from] crate::persistence::db::DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("event emission failed: {0}")]
    Event(#[from] crate::events::EventError),
    #[error("unknown task state in the ledger: {0}")]
    InvalidState(String),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
    #[error("parent task {0} does not exist")]
    ParentNotFound(Uuid),
    #[error("dependency task {0} does not exist")]
    DependencyNotFound(Uuid),
    #[error("task {0} cannot depend on itself")]
    SelfDependency(Uuid),
    #[error("adding {dependent} -> {prerequisite} would create a dependency cycle")]
    CycleDetected { dependent: Uuid, prerequisite: Uuid },
    #[error("task {0} does not exist")]
    TaskNotFound(Uuid),
    #[error("task {0} is being cancelled; new child tasks are refused")]
    ParentCancelling(Uuid),
    #[error("budget error: {0}")]
    Budget(#[from] budget::BudgetError),
}

pub const EVENT_TASK_DELEGATED: &str = "TaskDelegated";
pub const EVENT_TASK_DEPENDENCY_ADDED: &str = "TaskDependencyAdded";
pub const EVENT_TASK_BECAME_READY: &str = "TaskBecameReady";
