//! Durable storage and transactional rules for the delegation DAG.
//!
//! Every mutation here happens inside one SQLite transaction: creating a child
//! with its edges, adding an edge with its cycle check, completing a task and
//! releasing its dependents. A rejected operation writes nothing.
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use crate::events::EventBus;
use crate::persistence::db::DatabaseConnectionPool;
use crate::persistence::migrations::apply_delegation_schema;
use crate::tasks::state::TaskState;
use crate::tasks::store::{Task, TaskStore};

use super::{
    ChildTaskSpec, DelegationError, EVENT_TASK_BECAME_READY, EVENT_TASK_DELEGATED,
    EVENT_TASK_DEPENDENCY_ADDED, TaskDependency,
};

/// The delegation surface over the shared task ledger.
pub struct DelegationKernel {
    task_store: TaskStore,
    event_bus: EventBus,
    pool: DatabaseConnectionPool,
}

impl DelegationKernel {
    /// Open the delegation DAG over an existing task ledger.
    pub fn open(task_store: TaskStore, event_bus: EventBus) -> Result<Self, DelegationError> {
        let pool = DatabaseConnectionPool::open(task_store.database_path())?;
        let conn = pool.connection()?;
        apply_delegation_schema(&conn)?;

        Ok(Self {
            task_store,
            event_bus,
            pool,
        })
    }

    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    // ── Creation ─────────────────────────────────────────────────────────────

    /// Create a child task with its dependency edges, atomically.
    ///
    /// The child starts in `Created`. It becomes `Ready` in the same
    /// transaction only if every prerequisite is already `Completed`.
    pub fn create_child(
        &self,
        parent_task_id: Uuid,
        spec: ChildTaskSpec,
    ) -> Result<Uuid, DelegationError> {
        self.create_child_inner(parent_task_id, spec, None)
    }

    /// Shared implementation for budgeted and unbudgeted creation.
    ///
    /// The transaction begins `IMMEDIATE`: when an allocation is requested, the
    /// parent's available envelope must be read and debited under the same write
    /// lock, or two concurrent creations could each see the full budget.
    pub(crate) fn create_child_inner(
        &self,
        parent_task_id: Uuid,
        spec: ChildTaskSpec,
        allocation_tokens: Option<i64>,
    ) -> Result<Uuid, DelegationError> {
        let mut connection = self.pool.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        require_task(
            &transaction,
            parent_task_id,
            DelegationError::ParentNotFound,
        )?;

        // Phase 6.1D — a child must not escape a cascade.
        //
        // Both checks are deliberate: the state is the fast path the coordinator
        // sets first, and the intent row is the durable record. If either says
        // "cancelling", the child is refused. Because this transaction is
        // IMMEDIATE, the check and the insert serialize against the coordinator's
        // propagation pass: either the child exists before enumeration (and is
        // cascaded) or the request commits first (and creation is refused).
        let parent_state: String = transaction.query_row(
            "SELECT state FROM tasks WHERE task_id = ?1",
            [parent_task_id.to_string()],
            |row| row.get(0),
        )?;
        if parent_state == crate::tasks::state::TaskState::Cancelling.as_str() {
            return Err(DelegationError::ParentCancelling(parent_task_id));
        }
        let intent_exists: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM task_cancellation_intents \
             WHERE task_id = ?1 AND status <> 'Completed'",
            [parent_task_id.to_string()],
            |row| row.get(0),
        )?;
        if intent_exists > 0 {
            return Err(DelegationError::ParentCancelling(parent_task_id));
        }

        let task_id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "INSERT INTO tasks \
             (task_id, title, state, priority, retry_count, created_at, updated_at, \
              parent_task_id, assigned_agent_id, objective) \
             VALUES (?1, ?2, 'Created', 0, 0, ?3, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                task_id.to_string(),
                spec.title,
                now,
                parent_task_id.to_string(),
                spec.assigned_agent_id,
                spec.objective,
            ],
        )?;

        for prerequisite in &spec.dependencies {
            insert_dependency(&transaction, task_id, *prerequisite)?;
        }

        let allocated = match allocation_tokens {
            Some(tokens) => {
                super::budget::allocate_child_in_transaction(
                    &transaction,
                    parent_task_id,
                    task_id,
                    tokens,
                )?;
                Some(tokens)
            }
            None => None,
        };

        let promoted = promote_if_ready(&transaction, task_id)?;

        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            EVENT_TASK_DELEGATED,
            serde_json::json!({
                "task_id": task_id,
                "parent_task_id": parent_task_id,
                "dependencies": spec.dependencies,
                "allocated_tokens": allocated,
                "state": if promoted { "Ready" } else { "Created" },
            }),
        )?;

        if promoted {
            emit_ready(&self.event_bus, &transaction, task_id)?;
        }

        transaction.commit()?;
        Ok(task_id)
    }

    /// Add a dependency edge to an existing task, rejecting cycles.
    pub fn add_dependency(
        &self,
        dependent_task_id: Uuid,
        prerequisite_task_id: Uuid,
    ) -> Result<(), DelegationError> {
        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction()?;

        insert_dependency(&transaction, dependent_task_id, prerequisite_task_id)?;
        promote_if_ready(&transaction, dependent_task_id)?;

        self.event_bus.emit_event_with_connection(
            &transaction,
            Some(&dependent_task_id.to_string()),
            EVENT_TASK_DEPENDENCY_ADDED,
            serde_json::json!({
                "dependent_task_id": dependent_task_id,
                "prerequisite_task_id": prerequisite_task_id,
            }),
        )?;

        transaction.commit()?;
        Ok(())
    }

    // ── Completion and release ───────────────────────────────────────────────

    /// Complete a task and release its eligible dependents in one transaction.
    ///
    /// A dependent whose prerequisites are not all `Completed` stays `Created`;
    /// readiness is never assumed.
    pub fn complete_task(&self, task_id: Uuid) -> Result<Vec<Uuid>, DelegationError> {
        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction()?;

        let state: String = transaction
            .query_row(
                "SELECT state FROM tasks WHERE task_id = ?1",
                [task_id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(DelegationError::TaskNotFound(task_id))?;
        let from = TaskState::try_from(state.as_str())
            .map_err(|_| DelegationError::InvalidState(state.clone()))?;

        self.task_store.transition_state_with_connection(
            &transaction,
            task_id,
            from,
            TaskState::Completed,
        )?;

        let mut dependents = Vec::new();
        // Dependents are tasks that carry an edge *to* this task — not its
        // children, which are a different relation.
        let mut statement = transaction.prepare(
            "SELECT t.task_id FROM tasks t \
             JOIN task_dependencies d ON d.dependent_task_id = t.task_id \
             WHERE d.prerequisite_task_id = ?1 AND t.state = 'Created'",
        )?;
        let candidate_rows =
            statement.query_map([task_id.to_string()], |row| row.get::<_, String>("task_id"))?;
        for candidate in candidate_rows {
            let dependent = Uuid::parse_str(&candidate?)?;
            if promote_if_ready(&transaction, dependent)? {
                dependents.push(dependent);
            }
        }
        drop(statement);

        for dependent in &dependents {
            emit_ready(&self.event_bus, &transaction, *dependent)?;
        }

        transaction.commit()?;
        Ok(dependents)
    }

    // ── Reads ────────────────────────────────────────────────────────────────

    pub fn children(&self, parent_task_id: Uuid) -> Result<Vec<Task>, DelegationError> {
        let connection = self.pool.connection()?;
        let mut statement = connection.prepare(
            "SELECT task_id, title, state, priority, retry_count, created_at, updated_at \
             FROM tasks WHERE parent_task_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = statement.query_map([parent_task_id.to_string()], |row| {
            let state: String = row.get("state")?;
            Ok((
                row.get::<_, String>("task_id")?,
                row.get::<_, String>("title")?,
                state,
                row.get::<_, i64>("priority")?,
                row.get::<_, i64>("retry_count")?,
                row.get::<_, String>("created_at")?,
                row.get::<_, String>("updated_at")?,
            ))
        })?;

        let mut tasks = Vec::new();
        for row in rows {
            let (task_id, title, state, priority, retry_count, created_at, updated_at) = row?;
            let state = TaskState::try_from(state.as_str())
                .map_err(|_| DelegationError::InvalidState(state.clone()))?;
            tasks.push(Task {
                task_id: Uuid::parse_str(&task_id)?,
                title,
                state,
                priority,
                retry_count,
                created_at,
                updated_at,
            });
        }
        Ok(tasks)
    }

    pub fn dependencies_of(&self, task_id: Uuid) -> Result<Vec<TaskDependency>, DelegationError> {
        let connection = self.pool.connection()?;
        let mut statement = connection.prepare(
            "SELECT dependent_task_id, prerequisite_task_id, created_at \
             FROM task_dependencies WHERE dependent_task_id = ?1 \
             ORDER BY created_at ASC",
        )?;
        let rows = statement.query_map([task_id.to_string()], |row| {
            Ok((
                row.get::<_, String>("dependent_task_id")?,
                row.get::<_, String>("prerequisite_task_id")?,
                row.get::<_, String>("created_at")?,
            ))
        })?;

        let mut dependencies = Vec::new();
        for row in rows {
            let (dependent, prerequisite, created_at) = row?;
            dependencies.push(TaskDependency {
                dependent_task_id: Uuid::parse_str(&dependent)?,
                prerequisite_task_id: Uuid::parse_str(&prerequisite)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| DelegationError::InvalidState(created_at.clone()))?
                    .with_timezone(&Utc),
            });
        }
        Ok(dependencies)
    }

    /// Every edge in the DAG. Used by the restart-durability assertion.
    pub fn all_dependencies(&self) -> Result<Vec<TaskDependency>, DelegationError> {
        let connection = self.pool.connection()?;
        let mut statement = connection.prepare(
            "SELECT dependent_task_id, prerequisite_task_id, created_at \
             FROM task_dependencies ORDER BY created_at ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>("dependent_task_id")?,
                row.get::<_, String>("prerequisite_task_id")?,
                row.get::<_, String>("created_at")?,
            ))
        })?;

        let mut dependencies = Vec::new();
        for row in rows {
            let (dependent, prerequisite, created_at) = row?;
            dependencies.push(TaskDependency {
                dependent_task_id: Uuid::parse_str(&dependent)?,
                prerequisite_task_id: Uuid::parse_str(&prerequisite)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| DelegationError::InvalidState(created_at.clone()))?
                    .with_timezone(&Utc),
            });
        }
        Ok(dependencies)
    }

    /// True when `candidate` is reachable from `task` by following prerequisites.
    pub fn depends_transitively_on(
        &self,
        task: Uuid,
        candidate: Uuid,
    ) -> Result<bool, DelegationError> {
        let connection = self.pool.connection()?;
        has_ancestor(&connection, task, candidate)
    }
}

// ── Primitives shared by the transactional paths ─────────────────────────────

fn require_task(
    connection: &Connection,
    task_id: Uuid,
    missing: impl FnOnce(Uuid) -> DelegationError,
) -> Result<(), DelegationError> {
    let exists: i64 = connection.query_row(
        "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
        [task_id.to_string()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(missing(task_id));
    }
    Ok(())
}

/// Insert one edge, rejecting self-dependency, unknown tasks, and cycles.
fn insert_dependency(
    connection: &Connection,
    dependent_task_id: Uuid,
    prerequisite_task_id: Uuid,
) -> Result<(), DelegationError> {
    if dependent_task_id == prerequisite_task_id {
        return Err(DelegationError::SelfDependency(dependent_task_id));
    }

    require_task(connection, dependent_task_id, DelegationError::TaskNotFound)?;
    require_task(
        connection,
        prerequisite_task_id,
        DelegationError::DependencyNotFound,
    )?;

    // A cycle exists iff the prerequisite already depends on the dependent.
    if has_ancestor(connection, prerequisite_task_id, dependent_task_id)? {
        return Err(DelegationError::CycleDetected {
            dependent: dependent_task_id,
            prerequisite: prerequisite_task_id,
        });
    }

    connection.execute(
        "INSERT OR IGNORE INTO task_dependencies \
         (dependent_task_id, prerequisite_task_id, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            dependent_task_id.to_string(),
            prerequisite_task_id.to_string(),
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Does `start` depend, directly or transitively, on `candidate`?
fn has_ancestor(
    connection: &Connection,
    start: Uuid,
    candidate: Uuid,
) -> Result<bool, DelegationError> {
    let found: i64 = connection.query_row(
        "WITH RECURSIVE ancestors(task_id) AS ( \
             SELECT prerequisite_task_id FROM task_dependencies WHERE dependent_task_id = ?1 \
             UNION \
             SELECT td.prerequisite_task_id FROM task_dependencies td \
             JOIN ancestors a ON td.dependent_task_id = a.task_id \
         ) \
         SELECT COUNT(*) FROM ancestors WHERE task_id = ?2",
        rusqlite::params![start.to_string(), candidate.to_string()],
        |row| row.get(0),
    )?;
    Ok(found > 0)
}

/// `Created → Ready` when every prerequisite is `Completed`.
///
/// The `NOT EXISTS` clause is evaluated inside the caller's transaction, so a
/// concurrent completion cannot release a task whose prerequisites are still
/// outstanding.
fn promote_if_ready(connection: &Connection, task_id: Uuid) -> Result<bool, DelegationError> {
    let changed = connection.execute(
        "UPDATE tasks SET state = 'Ready', updated_at = ?2 \
         WHERE task_id = ?1 AND state = 'Created' \
           AND NOT EXISTS ( \
               SELECT 1 FROM task_dependencies d \
               JOIN tasks t ON t.task_id = d.prerequisite_task_id \
               WHERE d.dependent_task_id = ?1 AND t.state <> 'Completed' \
           )",
        rusqlite::params![task_id.to_string(), Utc::now().to_rfc3339()],
    )?;
    Ok(changed == 1)
}

fn emit_ready(
    event_bus: &EventBus,
    connection: &Connection,
    task_id: Uuid,
) -> Result<(), DelegationError> {
    event_bus.emit_event_with_connection(
        connection,
        Some(&task_id.to_string()),
        EVENT_TASK_BECAME_READY,
        serde_json::json!({
            "task_id": task_id,
            "state": "Ready",
            "reason": "all prerequisites completed",
        }),
    )?;
    Ok(())
}
