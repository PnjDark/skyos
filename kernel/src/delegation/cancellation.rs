//! Phase 6.1D — hierarchical cancellation.
//!
//! # The distinction this module exists to preserve
//!
//! Cancellation *intent* and cancellation *completion* are different events.
//! A parent may request cancellation of its descendants, but it cannot declare
//! them cancelled because it sent a request. The terminal `Cancelled` state is
//! earned by three durable facts:
//!
//! 1. every descendant is terminal,
//! 2. every live cooperative execution acknowledged *for this intent*, and
//! 3. no acknowledgement came from a superseded execution.
//!
//! # Execution identity
//!
//! Acknowledgements are scoped to an `execution_id`, not to the task. A task can
//! run more than once; an acknowledgement from an earlier loop must never be
//! read as proof that a later one stopped. `task_executions` keeps at most one
//! `Active` row per task (partial unique index), and an acknowledgement only
//! counts if it names that row.
//!
//! # Escalation is not cancellation
//!
//! When a deadline passes without an acknowledgement the intent becomes
//! `Escalated`, never `Cancelled`. An operator must resolve it explicitly.
use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::events::EventBus;
use crate::identity::{
    ActorAuthenticator, ActorClaim, ActorKind, AuthError,
};
use crate::persistence::db::DatabaseConnectionPool;
use crate::persistence::migrations::apply_cancellation_schema;
use crate::tasks::state::TaskState;
use crate::tasks::store::{TaskStore, TaskStoreError};

pub const EVENT_CANCELLATION_REQUESTED: &str = "CancellationRequested";
pub const EVENT_CANCELLATION_PROPAGATED: &str = "CancellationPropagated";
pub const EVENT_CANCELLATION_ACKNOWLEDGED: &str = "CancellationAcknowledged";
pub const EVENT_CANCELLATION_ESCALATED: &str = "CancellationEscalated";
pub const EVENT_TASK_CANCELLED: &str = "TaskCancelled";
pub const EVENT_CANCELLATION_REOPENED: &str = "CancellationReopened";

/// Default time an execution has to acknowledge before the cascade escalates.
pub const DEFAULT_ACK_TIMEOUT_SECS: i64 = 60;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentStatus {
    /// Intent durable; the task is not yet visibly cancelling.
    Requested,
    /// Descendants are being marked.
    Propagating,
    /// All nodes marked; waiting for acknowledgements.
    AwaitingWorkers,
    /// Deadline expired without acknowledgement. Operator action required.
    Escalated,
    /// This node reached terminal cancellation.
    Completed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "Requested",
            Self::Propagating => "Propagating",
            Self::AwaitingWorkers => "AwaitingWorkers",
            Self::Escalated => "Escalated",
            Self::Completed => "Completed",
        }
    }

    pub fn is_open(self) -> bool {
        !matches!(self, Self::Completed)
    }
}

impl TryFrom<&str> for IntentStatus {
    type Error = CancellationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Requested" => Ok(Self::Requested),
            "Propagating" => Ok(Self::Propagating),
            "AwaitingWorkers" => Ok(Self::AwaitingWorkers),
            "Escalated" => Ok(Self::Escalated),
            "Completed" => Ok(Self::Completed),
            other => Err(CancellationError::InvalidStatus(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationIntent {
    pub intent_id: Uuid,
    pub task_id: Uuid,
    pub root_task_id: Uuid,
    pub requested_by_actor: String,
    pub auth_method: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub status: IntentStatus,
    pub escalated_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord {
    pub execution_id: Uuid,
    pub task_id: Uuid,
    pub agent_id: String,
    pub started_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgement {
    pub acknowledgement_id: Uuid,
    pub intent_id: Uuid,
    pub task_id: Uuid,
    pub execution_id: Uuid,
    pub last_step_number: Option<usize>,
    pub final_status: String,
    pub acknowledged_at: DateTime<Utc>,
}

/// What an operator decided about an escalated cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationResolution {
    /// The operator confirms termination: the task goes to `Cancelled`.
    ConfirmCancellation,
    /// The operator reopens the task: it returns to `Ready`, and its worker may
    /// run again. The cancellation record is closed and is not re-armed.
    Reopen,
}

/// Progress of one cascade pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CascadeProgress {
    pub root_task_id: Option<Uuid>,
    pub marked: Vec<Uuid>,
    pub cancelled: Vec<Uuid>,
    pub escalated: Vec<Uuid>,
    /// Nodes still `Cancelling` and waiting for a confirmation.
    pub awaiting: Vec<Uuid>,
}

#[derive(Debug, Error)]
pub enum CancellationError {
    #[error("database error: {0}")]
    Database(#[from] crate::persistence::db::DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("task store error: {0}")]
    TaskStore(#[from] TaskStoreError),
    #[error("event emission failed: {0}")]
    Event(#[from] crate::events::EventError),
    #[error("actor authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("actor '{id}' ({kind}) may not cancel tasks")]
    AgentNotPermitted { id: String, kind: String },
    #[error("task {0} does not exist")]
    TaskNotFound(Uuid),
    #[error("task {task_id} is already terminal ({state})")]
    TaskAlreadyTerminal { task_id: Uuid, state: String },
    #[error("task {task_id} already has a completed cancellation record; it cannot be cancelled again")]
    AlreadyResolved { task_id: Uuid },
    #[error("no active cancellation intent for task {0}")]
    NoActiveIntent(Uuid),
    #[error("execution {execution_id} is not the active execution for task {task_id}")]
    StaleExecution {
        task_id: Uuid,
        execution_id: Uuid,
    },
    #[error("cancellation {task_id} is {status}, not Escalated")]
    NotEscalated { task_id: Uuid, status: String },
    #[error("unknown cancellation status: '{0}'")]
    InvalidStatus(String),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
    #[error("invalid timestamp in cancellation ledger: {0}")]
    InvalidTimestamp(String),
    #[error("task {task_id} is {state}; it cannot be cancelled from this state")]
    IllegalTransition { task_id: Uuid, state: String },
    #[error("task {0} is being cancelled; new child tasks are refused")]
    ParentCancelling(Uuid),
}

// ── Store: execution identity ───────────────────────────────────────────────

/// Durable record of cooperative executions and their acknowledgements.
#[derive(Debug, Clone)]
pub struct CancellationStore {
    pool: DatabaseConnectionPool,
}

impl CancellationStore {
    pub fn open(db_path: impl AsRef<std::path::Path>) -> Result<Self, CancellationError> {
        let pool = DatabaseConnectionPool::open(db_path)?;
        let connection = pool.connection()?;
        apply_cancellation_schema(&connection)?;
        Ok(Self { pool })
    }

    pub fn connection(&self) -> Result<Connection, CancellationError> {
        Ok(self.pool.connection()?)
    }

    /// Register a new cooperative execution for `task_id`.
    ///
    /// Any previously active execution for the same task is marked `Stopped`
    /// (superseded) inside the same transaction, so there is never more than one
    /// active loop and an old acknowledgement cannot be attributed to this one.
    pub fn begin_execution(
        &self,
        task_id: Uuid,
        agent_id: &str,
    ) -> Result<Uuid, CancellationError> {
        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "UPDATE task_executions \
             SET state = 'Stopped', stopped_at = ?1, stop_reason = 'superseded' \
             WHERE task_id = ?2 AND state = 'Active'",
            params![now, task_id.to_string()],
        )?;

        let execution_id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO task_executions \
             (execution_id, task_id, agent_id, started_at, state) \
             VALUES (?1, ?2, ?3, ?4, 'Active')",
            params![
                execution_id.to_string(),
                task_id.to_string(),
                agent_id,
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(execution_id)
    }

    pub fn end_execution(
        &self,
        execution_id: Uuid,
        reason: &str,
    ) -> Result<(), CancellationError> {
        let connection = self.pool.connection()?;
        connection.execute(
            "UPDATE task_executions \
             SET state = 'Stopped', stopped_at = ?1, stop_reason = ?2 \
             WHERE execution_id = ?3 AND state = 'Active'",
            params![Utc::now().to_rfc3339(), reason, execution_id.to_string()],
        )?;
        Ok(())
    }

    pub fn active_execution(
        &self,
        task_id: Uuid,
    ) -> Result<Option<ExecutionRecord>, CancellationError> {
        let connection = self.pool.connection()?;
        let row = connection
            .query_row(
                "SELECT execution_id, task_id, agent_id, started_at \
                 FROM task_executions WHERE task_id = ?1 AND state = 'Active'",
                [task_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((execution_id, task_id, agent_id, started_at)) = row else {
            return Ok(None);
        };
        Ok(Some(ExecutionRecord {
            execution_id: Uuid::parse_str(&execution_id)?,
            task_id: Uuid::parse_str(&task_id)?,
            agent_id,
            started_at: parse_time(&started_at)?,
            active: true,
        }))
    }

    /// Record that `execution_id` observed cancellation and stopped.
    ///
    /// The acknowledgement is scoped to the intent *and* the execution: a stale
    /// execution id is refused rather than silently accepted.
    pub fn acknowledge(
        &self,
        task_id: Uuid,
        execution_id: Uuid,
        last_step_number: Option<usize>,
        final_status: &str,
    ) -> Result<Acknowledgement, CancellationError> {
        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let intent = load_open_intent(&transaction, task_id)?
            .ok_or(CancellationError::NoActiveIntent(task_id))?;

        // The acknowledgement must name the currently active execution.
        let active: Option<String> = transaction
            .query_row(
                "SELECT execution_id FROM task_executions \
                 WHERE task_id = ?1 AND state = 'Active'",
                [task_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if active.as_deref() != Some(&execution_id.to_string()) {
            return Err(CancellationError::StaleExecution {
                task_id,
                execution_id,
            });
        }

        let existing = transaction
            .query_row(
                "SELECT acknowledgement_id, last_step_number, final_status, acknowledged_at \
                 FROM task_cancellation_acknowledgements \
                 WHERE intent_id = ?1 AND execution_id = ?2",
                params![intent.intent_id.to_string(), execution_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;

        let acknowledgement = match existing {
            Some((id, step, status, at)) => Acknowledgement {
                acknowledgement_id: Uuid::parse_str(&id)?,
                intent_id: intent.intent_id,
                task_id,
                execution_id,
                last_step_number: step.map(|value| value as usize),
                final_status: status,
                acknowledged_at: parse_time(&at)?,
            },
            None => {
                let acknowledgement = Acknowledgement {
                    acknowledgement_id: Uuid::new_v4(),
                    intent_id: intent.intent_id,
                    task_id,
                    execution_id,
                    last_step_number,
                    final_status: final_status.to_string(),
                    acknowledged_at: Utc::now(),
                };
                transaction.execute(
                    "INSERT INTO task_cancellation_acknowledgements \
                     (acknowledgement_id, intent_id, task_id, execution_id, last_step_number, \
                      final_status, acknowledged_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        acknowledgement.acknowledgement_id.to_string(),
                        intent.intent_id.to_string(),
                        task_id.to_string(),
                        execution_id.to_string(),
                        last_step_number.map(|value| value as i64),
                        final_status,
                        acknowledgement.acknowledged_at.to_rfc3339(),
                    ],
                )?;
                transaction.execute(
                    "UPDATE task_executions \
                     SET state = 'Stopped', stopped_at = ?1, stop_reason = 'cancelled' \
                     WHERE execution_id = ?2 AND state = 'Active'",
                    params![
                        acknowledgement.acknowledged_at.to_rfc3339(),
                        execution_id.to_string()
                    ],
                )?;
                acknowledgement
            }
        };

        transaction.commit()?;
        Ok(acknowledgement)
    }

    pub fn intent_for(
        &self,
        task_id: Uuid,
    ) -> Result<Option<CancellationIntent>, CancellationError> {
        let connection = self.pool.connection()?;
        load_intent(&connection, task_id)
    }
}

// ── Coordinator ─────────────────────────────────────────────────────────────

/// Owns the cancellation cascade.
pub struct CancellationCoordinator {
    task_store: TaskStore,
    event_bus: EventBus,
    pool: DatabaseConnectionPool,
    authenticator: std::sync::Arc<dyn ActorAuthenticator>,
    ack_timeout: Duration,
}

impl CancellationCoordinator {
    pub fn open(
        task_store: TaskStore,
        event_bus: EventBus,
        authenticator: std::sync::Arc<dyn ActorAuthenticator>,
    ) -> Result<Self, CancellationError> {
        let pool = DatabaseConnectionPool::open(task_store.database_path())?;
        let connection = pool.connection()?;
        apply_cancellation_schema(&connection)?;
        crate::persistence::migrations::apply_delegation_schema(&connection)?;
        Ok(Self {
            task_store,
            event_bus,
            pool,
            authenticator,
            ack_timeout: Duration::seconds(DEFAULT_ACK_TIMEOUT_SECS),
        })
    }

    pub fn with_ack_timeout(mut self, timeout: Duration) -> Self {
        self.ack_timeout = timeout;
        self
    }

    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    // ── Request ──────────────────────────────────────────────────────────────

    /// Persist cancellation intent for `task_id` and begin the cascade.
    ///
    /// Idempotent: a second request while an intent is open returns that intent
    /// unchanged. A completed record refuses a new request explicitly rather
    /// than silently doing nothing.
    pub fn request(
        &self,
        claim: &ActorClaim,
        task_id: Uuid,
        reason: &str,
    ) -> Result<CancellationIntent, CancellationError> {
        let actor = self.authenticate(claim)?;

        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let state = load_state(&transaction, task_id)?
            .ok_or(CancellationError::TaskNotFound(task_id))?;

        if let Some(existing) = load_intent(&transaction, task_id)? {
            if existing.status == IntentStatus::Completed {
                if existing.escalated_at.is_some() && state != TaskState::Cancelled {
                    // Reopened by an operator: the record is closed.
                    return Err(CancellationError::AlreadyResolved { task_id });
                }
                return Ok(existing);
            }
            return Ok(existing);
        }

        if state.is_terminal() {
            return Err(CancellationError::TaskAlreadyTerminal {
                task_id,
                state: state.to_string(),
            });
        }
        if !state.can_transition_to(TaskState::Cancelling) {
            return Err(CancellationError::IllegalTransition {
                task_id,
                state: state.to_string(),
            });
        }

        let now = Utc::now();
        let intent = CancellationIntent {
            intent_id: Uuid::new_v4(),
            task_id,
            root_task_id: task_id,
            requested_by_actor: actor.id().to_string(),
            auth_method: actor.method().as_str().to_string(),
            reason: reason.to_string(),
            requested_at: now,
            deadline_at: now + self.ack_timeout,
            status: IntentStatus::Requested,
            escalated_at: None,
            completed_at: None,
        };

        insert_intent(&transaction, &intent)?;
        self.task_store.transition_state_with_connection(
            &transaction,
            task_id,
            state,
            TaskState::Cancelling,
        )?;
        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            EVENT_CANCELLATION_REQUESTED,
            serde_json::json!({
                "task_id": task_id,
                "intent_id": intent.intent_id,
                "actor_id": actor.id(),
                "auth_method": actor.method().as_str(),
                "reason": reason,
                "deadline_at": intent.deadline_at,
            }),
        )?;
        transaction.commit()?;

        self.propagate(task_id)?;
        Ok(intent)
    }

    // ── Propagation ──────────────────────────────────────────────────────────

    /// Mark every non-terminal descendant, then attempt to finalize.
    ///
    /// Resumable: everything is derived from durable rows, never from an
    /// in-memory traversal cursor.
    pub fn propagate(&self, root_task_id: Uuid) -> Result<CascadeProgress, CancellationError> {
        let mut progress = CascadeProgress {
            root_task_id: Some(root_task_id),
            ..Default::default()
        };

        let descendants = {
            let connection = self.pool.connection()?;
            descendants_of(&connection, root_task_id)?
        };

        for descendant in &descendants {
            let mut connection = self.pool.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

            let state = load_state(&transaction, *descendant)?
                .ok_or(CancellationError::TaskNotFound(*descendant))?;
            if state.is_terminal() {
                // Invariant 7: finished work keeps its state and artifacts.
                continue;
            }
            if load_intent(&transaction, *descendant)?.is_none() {
                let now = Utc::now();
                let intent = CancellationIntent {
                    intent_id: Uuid::new_v4(),
                    task_id: *descendant,
                    root_task_id,
                    requested_by_actor: "cascade".to_string(),
                    auth_method: "cascade".to_string(),
                    reason: "descendant of a cancelled task".to_string(),
                    requested_at: now,
                    deadline_at: now + self.ack_timeout,
                    status: IntentStatus::Propagating,
                    escalated_at: None,
                    completed_at: None,
                };
                insert_intent(&transaction, &intent)?;
                if state.can_transition_to(TaskState::Cancelling) {
                    self.task_store.transition_state_with_connection(
                        &transaction,
                        *descendant,
                        state,
                        TaskState::Cancelling,
                    )?;
                }
                self.event_bus.emit_event_with_connection(
                    &transaction,
                    Some(&descendant.to_string()),
                    EVENT_CANCELLATION_PROPAGATED,
                    serde_json::json!({
                        "task_id": descendant,
                        "root_task_id": root_task_id,
                        "intent_id": intent.intent_id,
                    }),
                )?;
            }
            transaction.commit()?;
            progress.marked.push(*descendant);
        }

        // Everything is marked: move open intents into the waiting state.
        {
            let connection = self.pool.connection()?;
            connection.execute(
                "UPDATE task_cancellation_intents SET status = 'AwaitingWorkers' \
                 WHERE root_task_id = ?1 AND status IN ('Requested', 'Propagating')",
                [root_task_id.to_string()],
            )?;
        }

        self.finalize(root_task_id, &mut progress)?;
        Ok(progress)
    }

    /// Try to finish every node of a cascade, deepest first.
    fn finalize(
        &self,
        root_task_id: Uuid,
        progress: &mut CascadeProgress,
    ) -> Result<(), CancellationError> {
        let nodes = {
            let connection = self.pool.connection()?;
            cancellation_nodes(&connection, root_task_id)?
        };

        // Repeat until stable: a parent can only finish after its children.
        for _ in 0..=nodes.len() {
            let mut changed = false;

            for node in &nodes {
                let mut connection = self.pool.connection()?;
                let transaction =
                    connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

                let Some(intent) = load_intent(&transaction, *node)? else {
                    continue;
                };
                if !intent.status.is_open() {
                    continue;
                }
                let state = load_state(&transaction, *node)?
                    .ok_or(CancellationError::TaskNotFound(*node))?;

                if state == TaskState::Cancelling {
                    let quiescent = is_quiescent(&transaction, *node, intent.intent_id)?;
                    let open_descendants = open_descendants(&transaction, *node)?;

                    if quiescent && open_descendants == 0 {
                        self.task_store.transition_state_with_connection(
                            &transaction,
                            *node,
                            TaskState::Cancelling,
                            TaskState::Cancelled,
                        )?;
                        transaction.execute(
                            "UPDATE task_cancellation_intents \
                             SET status = 'Completed', completed_at = ?1 WHERE intent_id = ?2",
                            params![Utc::now().to_rfc3339(), intent.intent_id.to_string()],
                        )?;
                        self.event_bus.emit_event_with_connection(
                            &transaction,
                            Some(&node.to_string()),
                            EVENT_TASK_CANCELLED,
                            serde_json::json!({
                                "task_id": node,
                                "root_task_id": root_task_id,
                                "intent_id": intent.intent_id,
                            }),
                        )?;
                        progress.cancelled.push(*node);
                        changed = true;
                    } else if !quiescent && Utc::now() >= intent.deadline_at {
                        // A live execution has not acknowledged. Escalate; never
                        // manufacture a `Cancelled`.
                        self.task_store.transition_state_with_connection(
                            &transaction,
                            *node,
                            TaskState::Cancelling,
                            TaskState::Escalated,
                        )?;
                        transaction.execute(
                            "UPDATE task_cancellation_intents \
                             SET status = 'Escalated', escalated_at = ?1 WHERE intent_id = ?2",
                            params![Utc::now().to_rfc3339(), intent.intent_id.to_string()],
                        )?;
                        self.event_bus.emit_event_with_connection(
                            &transaction,
                            Some(&node.to_string()),
                            EVENT_CANCELLATION_ESCALATED,
                            serde_json::json!({
                                "task_id": node,
                                "intent_id": intent.intent_id,
                                "reason": "acknowledgement deadline expired",
                            }),
                        )?;
                        progress.escalated.push(*node);
                        changed = true;
                    } else {
                        progress.awaiting.push(*node);
                    }
                }

                transaction.commit()?;
            }

            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// Scan every open cascade and advance it. Safe to call on startup and
    /// periodically.
    pub fn tick(&self) -> Result<Vec<CascadeProgress>, CancellationError> {
        let roots = {
            let connection = self.pool.connection()?;
            let mut statement = connection.prepare(
                "SELECT DISTINCT root_task_id FROM task_cancellation_intents \
                 WHERE status <> 'Completed'",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let mut roots = Vec::new();
            for root in rows {
                roots.push(Uuid::parse_str(&root?)?);
            }
            roots
        };

        let mut results = Vec::new();
        for root in roots {
            results.push(self.propagate(root)?);
        }
        Ok(results)
    }

    // ── Escalation resolution ────────────────────────────────────────────────

    /// Resolve an escalated cancellation. Never called implicitly.
    pub fn resolve_escalated(
        &self,
        claim: &ActorClaim,
        task_id: Uuid,
        resolution: EscalationResolution,
    ) -> Result<TaskState, CancellationError> {
        let actor = self.authenticate(claim)?;

        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let intent = load_intent(&transaction, task_id)?
            .ok_or(CancellationError::NoActiveIntent(task_id))?;
        if intent.status != IntentStatus::Escalated {
            return Err(CancellationError::NotEscalated {
                task_id,
                status: intent.status.as_str().to_string(),
            });
        }
        let state = load_state(&transaction, task_id)?
            .ok_or(CancellationError::TaskNotFound(task_id))?;

        let (target, event) = match resolution {
            EscalationResolution::ConfirmCancellation => {
                // Escalated -> Cancelling -> Cancelled, both legal edges.
                self.task_store.transition_state_with_connection(
                    &transaction,
                    task_id,
                    state,
                    TaskState::Cancelling,
                )?;
                self.task_store.transition_state_with_connection(
                    &transaction,
                    task_id,
                    TaskState::Cancelling,
                    TaskState::Cancelled,
                )?;
                (TaskState::Cancelled, EVENT_TASK_CANCELLED)
            }
            EscalationResolution::Reopen => {
                self.task_store.transition_state_with_connection(
                    &transaction,
                    task_id,
                    state,
                    TaskState::Ready,
                )?;
                (TaskState::Ready, EVENT_CANCELLATION_REOPENED)
            }
        };

        transaction.execute(
            "UPDATE task_cancellation_intents \
             SET status = 'Completed', completed_at = ?1 WHERE intent_id = ?2",
            params![Utc::now().to_rfc3339(), intent.intent_id.to_string()],
        )?;
        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            event,
            serde_json::json!({
                "task_id": task_id,
                "intent_id": intent.intent_id,
                "actor_id": actor.id(),
                "resolution": match resolution {
                    EscalationResolution::ConfirmCancellation => "ConfirmedCancellation",
                    EscalationResolution::Reopen => "Reopened",
                },
            }),
        )?;
        transaction.commit()?;
        Ok(target)
    }

    fn authenticate(
        &self,
        claim: &ActorClaim,
    ) -> Result<crate::identity::AuthenticatedActor, CancellationError> {
        let verified = self.authenticator.verify(claim)?;
        if verified.kind == ActorKind::Agent {
            return Err(CancellationError::AgentNotPermitted {
                id: verified.id,
                kind: verified.kind.as_str().to_string(),
            });
        }
        Ok(crate::identity::AuthenticatedActor::from_verified(verified))
    }
}

// ── Queries ─────────────────────────────────────────────────────────────────

fn parse_time(raw: &str) -> Result<DateTime<Utc>, CancellationError> {
    Ok(DateTime::parse_from_rfc3339(raw)
        .map_err(|_| CancellationError::InvalidTimestamp(raw.to_string()))?
        .with_timezone(&Utc))
}

fn load_state(
    connection: &Connection,
    task_id: Uuid,
) -> Result<Option<TaskState>, CancellationError> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT state FROM tasks WHERE task_id = ?1",
            [task_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    match raw {
        Some(state) => TaskState::try_from(state.as_str())
            .map(Some)
            .map_err(|_| CancellationError::InvalidStatus(state)),
        None => Ok(None),
    }
}

fn load_intent(
    connection: &Connection,
    task_id: Uuid,
) -> Result<Option<CancellationIntent>, CancellationError> {
    let row = connection
        .query_row(
            "SELECT intent_id, task_id, root_task_id, requested_by_actor, auth_method, \
                    cancellation_reason, requested_at, deadline_at, status, escalated_at, \
                    completed_at \
             FROM task_cancellation_intents WHERE task_id = ?1",
            [task_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()?;

    let Some((
        intent_id,
        task_id,
        root_task_id,
        actor,
        auth_method,
        reason,
        requested_at,
        deadline_at,
        status,
        escalated_at,
        completed_at,
    )) = row
    else {
        return Ok(None);
    };

    Ok(Some(CancellationIntent {
        intent_id: Uuid::parse_str(&intent_id)?,
        task_id: Uuid::parse_str(&task_id)?,
        root_task_id: Uuid::parse_str(&root_task_id)?,
        requested_by_actor: actor,
        auth_method,
        reason,
        requested_at: parse_time(&requested_at)?,
        deadline_at: parse_time(&deadline_at)?,
        status: IntentStatus::try_from(status.as_str())?,
        escalated_at: escalated_at.map(|value| parse_time(&value)).transpose()?,
        completed_at: completed_at.map(|value| parse_time(&value)).transpose()?,
    }))
}

fn load_open_intent(
    connection: &Connection,
    task_id: Uuid,
) -> Result<Option<CancellationIntent>, CancellationError> {
    Ok(load_intent(connection, task_id)?.filter(|intent| intent.status.is_open()))
}

fn insert_intent(
    connection: &Connection,
    intent: &CancellationIntent,
) -> Result<(), CancellationError> {
    connection.execute(
        "INSERT INTO task_cancellation_intents \
         (intent_id, task_id, root_task_id, requested_by_actor, auth_method, \
          cancellation_reason, requested_at, deadline_at, status, escalated_at, completed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            intent.intent_id.to_string(),
            intent.task_id.to_string(),
            intent.root_task_id.to_string(),
            intent.requested_by_actor,
            intent.auth_method,
            intent.reason,
            intent.requested_at.to_rfc3339(),
            intent.deadline_at.to_rfc3339(),
            intent.status.as_str(),
            intent.escalated_at.map(|value| value.to_rfc3339()),
            intent.completed_at.map(|value| value.to_rfc3339()),
        ],
    )?;
    Ok(())
}

fn descendants_of(
    connection: &Connection,
    root_task_id: Uuid,
) -> Result<Vec<Uuid>, CancellationError> {
    let mut statement = connection.prepare(
        "WITH RECURSIVE descendants(task_id) AS ( \
             SELECT task_id FROM tasks WHERE parent_task_id = ?1 \
             UNION \
             SELECT t.task_id FROM tasks t JOIN descendants d ON t.parent_task_id = d.task_id \
         ) \
         SELECT task_id FROM descendants",
    )?;
    let rows = statement.query_map([root_task_id.to_string()], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(Uuid::parse_str(&row?)?);
    }
    Ok(out)
}

/// Every node of this cascade that is still non-terminal (including the root).
fn cancellation_nodes(
    connection: &Connection,
    root_task_id: Uuid,
) -> Result<Vec<Uuid>, CancellationError> {
    let mut statement = connection.prepare(
        "SELECT task_id FROM task_cancellation_intents \
         WHERE root_task_id = ?1 AND status <> 'Completed'",
    )?;
    let rows = statement.query_map([root_task_id.to_string()], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(Uuid::parse_str(&row?)?);
    }
    Ok(out)
}

/// No live execution is left waiting to acknowledge *this intent*.
fn is_quiescent(
    connection: &Connection,
    task_id: Uuid,
    intent_id: Uuid,
) -> Result<bool, CancellationError> {
    let outstanding: i64 = connection.query_row(
        "SELECT COUNT(*) FROM task_executions e \
         WHERE e.task_id = ?1 AND e.state = 'Active' \
           AND NOT EXISTS ( \
               SELECT 1 FROM task_cancellation_acknowledgements a \
               WHERE a.intent_id = ?2 AND a.execution_id = e.execution_id \
           )",
        params![task_id.to_string(), intent_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(outstanding == 0)
}

/// Descendants that have not reached a terminal state.
fn open_descendants(
    connection: &Connection,
    task_id: Uuid,
) -> Result<i64, CancellationError> {
    let count: i64 = connection.query_row(
        "WITH RECURSIVE d(task_id) AS ( \
             SELECT task_id FROM tasks WHERE parent_task_id = ?1 \
             UNION \
             SELECT t.task_id FROM tasks t JOIN d ON t.parent_task_id = d.task_id \
         ) \
         SELECT COUNT(*) FROM d JOIN tasks t ON t.task_id = d.task_id \
         WHERE t.state NOT IN ('Completed', 'Failed', 'Cancelled')",
        [task_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(count)
}
