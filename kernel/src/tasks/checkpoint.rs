/// Durable execution ledger — Phase 5: Crash Recovery & Execution Semantics.
///
/// `CheckpointStore` writes one row per agent step into `task_checkpoints`
/// (created by M4_CHECKPOINT_SCHEMA).  Every write is designed to share the
/// *same* `rusqlite::Connection` that the caller uses for task-state updates
/// and event emission so that checkpoint, state, and event are always
/// atomically consistent within a single WAL transaction.
///
/// # Safety contract
///
/// - **`write_checkpoint`** must be called *before* the tool is dispatched
///   (status = `Dispatched`).
/// - **`mark_succeeded`** / **`mark_failed`** / **`mark_outcome_unknown`**
///   must be called *after* the result is observed, inside the same commit.
/// - Recovery uses `list_unresolved` to find rows with status `Dispatched`
///   or `Pending` after a crash.
use std::path::Path;

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::{
    db::{DatabaseConnectionPool, DatabaseError},
    migrations::M4_CHECKPOINT_SCHEMA,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// Retry contract declared per operation.
///
/// The recovery engine uses this to decide what to do when it finds an
/// interrupted invocation at startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SideEffectSemantics {
    /// The side effect is inherently safe to repeat with identical inputs.
    /// Recovery may re-dispatch without further reconciliation.
    Idempotent,
    /// The side effect cannot be safely repeated without risking duplication.
    /// Recovery must mark the step `Failed` and require agent plan revision.
    AtMostOnce,
    /// The side effect can be independently verified against physical evidence
    /// (file bytes, Git log, container state) before deciding whether to retry.
    Reconcilable,
}

impl SideEffectSemantics {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idempotent => "Idempotent",
            Self::AtMostOnce => "AtMostOnce",
            Self::Reconcilable => "Reconcilable",
        }
    }
}

impl TryFrom<&str> for SideEffectSemantics {
    type Error = CheckpointError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "Idempotent" => Ok(Self::Idempotent),
            "AtMostOnce" => Ok(Self::AtMostOnce),
            "Reconcilable" => Ok(Self::Reconcilable),
            other => Err(CheckpointError::InvalidSemantics(other.to_string())),
        }
    }
}

/// Status of a persisted checkpoint row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointStatus {
    /// Written before dispatch; tool has not yet been called.
    Pending,
    /// Dispatch has been issued; outcome is not yet known.
    Dispatched,
    /// Tool returned `ToolStatus::Succeeded` and the result was recorded.
    Succeeded,
    /// Tool returned a non-success status and the failure was recorded.
    Failed,
    /// Process crashed after dispatch but before the result was recorded.
    /// Recovery engine must classify and handle this before resumption.
    OutcomeUnknown,
}

impl CheckpointStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Dispatched => "Dispatched",
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::OutcomeUnknown => "OutcomeUnknown",
        }
    }
}

impl TryFrom<&str> for CheckpointStatus {
    type Error = CheckpointError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Dispatched" => Ok(Self::Dispatched),
            "Succeeded" => Ok(Self::Succeeded),
            "Failed" => Ok(Self::Failed),
            "OutcomeUnknown" => Ok(Self::OutcomeUnknown),
            other => Err(CheckpointError::InvalidStatus(other.to_string())),
        }
    }
}

/// Full row read back from `task_checkpoints`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCheckpoint {
    pub task_id: Uuid,
    pub agent_id: String,
    pub step_number: usize,
    pub invocation_id: Option<Uuid>,
    pub idempotency_key: Option<String>,
    pub semantics: SideEffectSemantics,
    pub tool_id: Option<String>,
    pub operation_id: Option<String>,
    pub status: CheckpointStatus,
    pub checkpoint_time: String,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("unknown semantics value: '{0}'")]
    InvalidSemantics(String),
    #[error("unknown status value: '{0}'")]
    InvalidStatus(String),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Kernel-owned durable execution ledger.
///
/// All mutating methods that accept a `&Connection` are designed to be called
/// from inside an existing transaction so the checkpoint write is atomic with
/// the task-state update and the event emission.
#[derive(Clone)]
pub struct CheckpointStore {
    pub(crate) pool: DatabaseConnectionPool,
}

impl CheckpointStore {
    /// Open (or create) the checkpoint store at `path`.
    ///
    /// Applies `M4_CHECKPOINT_SCHEMA` on the shared `runtime_state.db` — the
    /// same file used by `TaskStore` and `EventBus`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CheckpointError> {
        let pool = DatabaseConnectionPool::open(path)?;
        let conn = pool.connection()?;
        conn.execute_batch(M4_CHECKPOINT_SCHEMA)?;
        Ok(Self { pool })
    }

    // ── Write helpers (accept external Connection for shared transactions) ────

    /// Write a `Pending` checkpoint for an upcoming step.
    ///
    /// Call this *before* building the `ToolContext` so a crash between here
    /// and dispatch is recoverable.
    pub fn write_pending(
        conn: &Connection,
        task_id: Uuid,
        agent_id: &str,
        step_number: usize,
        semantics: &SideEffectSemantics,
    ) -> Result<(), CheckpointError> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO task_checkpoints \
             (task_id, agent_id, step_number, invocation_id, idempotency_key, semantics, \
              tool_id, operation_id, status, checkpoint_time) \
             VALUES (?1, ?2, ?3, NULL, NULL, ?4, NULL, NULL, 'Pending', ?5)",
            rusqlite::params![
                task_id.to_string(),
                agent_id,
                step_number as i64,
                semantics.as_str(),
                now,
            ],
        )?;
        Ok(())
    }

    /// Advance a `Pending` row to `Dispatched`, recording the invocation
    /// identity and operation details.
    ///
    /// Call this immediately before `UnifiedToolRegistry::dispatch`.
    pub fn mark_dispatched(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
        invocation_id: Uuid,
        idempotency_key: &str,
        tool_id: &str,
        operation_id: &str,
    ) -> Result<(), CheckpointError> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE task_checkpoints \
             SET invocation_id = ?1, idempotency_key = ?2, tool_id = ?3, operation_id = ?4, \
                 status = 'Dispatched', checkpoint_time = ?5 \
             WHERE task_id = ?6 AND step_number = ?7",
            rusqlite::params![
                invocation_id.to_string(),
                idempotency_key,
                tool_id,
                operation_id,
                now,
                task_id.to_string(),
                step_number as i64,
            ],
        )?;
        Ok(())
    }

    /// Mark a dispatched invocation `Succeeded`.
    pub fn mark_succeeded(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(conn, task_id, step_number, CheckpointStatus::Succeeded)
    }

    /// Mark a dispatched invocation `Failed`.
    pub fn mark_failed(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(conn, task_id, step_number, CheckpointStatus::Failed)
    }

    /// Mark a dispatched invocation `OutcomeUnknown`.
    ///
    /// Called by the recovery engine when it detects a `Dispatched` row
    /// with no subsequent `Succeeded` or `Failed` record.
    pub fn mark_outcome_unknown(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(conn, task_id, step_number, CheckpointStatus::OutcomeUnknown)
    }

    fn set_status(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
        status: CheckpointStatus,
    ) -> Result<(), CheckpointError> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE task_checkpoints SET status = ?1, checkpoint_time = ?2 \
             WHERE task_id = ?3 AND step_number = ?4",
            rusqlite::params![
                status.as_str(),
                now,
                task_id.to_string(),
                step_number as i64,
            ],
        )?;
        Ok(())
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    /// Return all checkpoints for `task_id`, ordered by step number ascending.
    pub fn list_for_task(&self, task_id: Uuid) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        self.query_checkpoints(&conn, Some(task_id))
    }

    /// Return every checkpoint whose status is `Dispatched` or `Pending`
    /// across all tasks.  Used by the recovery engine on startup.
    pub fn list_unresolved(&self) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(
            "SELECT task_id, agent_id, step_number, invocation_id, idempotency_key, \
                    semantics, tool_id, operation_id, status, checkpoint_time \
             FROM task_checkpoints \
             WHERE status IN ('Pending', 'Dispatched') \
             ORDER BY task_id, step_number ASC",
        )?;
        self.collect_rows(&mut stmt, [])
    }

    /// Return the most recent checkpoint for `task_id` (highest step_number).
    pub fn latest_for_task(
        &self,
        task_id: Uuid,
    ) -> Result<Option<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let row = conn
            .query_row(
                "SELECT task_id, agent_id, step_number, invocation_id, idempotency_key, \
                        semantics, tool_id, operation_id, status, checkpoint_time \
                 FROM task_checkpoints \
                 WHERE task_id = ?1 \
                 ORDER BY step_number DESC LIMIT 1",
                [task_id.to_string()],
                Self::map_row,
            )
            .optional()?;
        Ok(row.transpose()?)
    }

    // ── Private row mapping ───────────────────────────────────────────────────

    fn query_checkpoints(
        &self,
        conn: &Connection,
        task_id: Option<Uuid>,
    ) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let mut stmt = conn.prepare(
            "SELECT task_id, agent_id, step_number, invocation_id, idempotency_key, \
                    semantics, tool_id, operation_id, status, checkpoint_time \
             FROM task_checkpoints \
             WHERE task_id = ?1 \
             ORDER BY step_number ASC",
        )?;
        let id_str = task_id.map(|u| u.to_string()).unwrap_or_default();
        self.collect_rows(&mut stmt, rusqlite::params![id_str])
    }

    fn collect_rows(
        &self,
        stmt: &mut rusqlite::Statement<'_>,
        params: impl rusqlite::Params,
    ) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let rows = stmt.query_map(params, Self::map_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<TaskCheckpoint, CheckpointError>> {
        let task_id_str: String = row.get("task_id")?;
        let invocation_str: Option<String> = row.get("invocation_id")?;
        let semantics_str: String = row.get("semantics")?;
        let status_str: String = row.get("status")?;

        Ok((|| -> Result<TaskCheckpoint, CheckpointError> {
            let task_id = Uuid::parse_str(&task_id_str)?;
            let invocation_id = invocation_str
                .map(|s| Uuid::parse_str(&s))
                .transpose()?;
            let semantics = SideEffectSemantics::try_from(semantics_str.as_str())?;
            let status = CheckpointStatus::try_from(status_str.as_str())?;

            Ok(TaskCheckpoint {
                task_id,
                agent_id: row.get("agent_id")?,
                step_number: row.get::<_, i64>("step_number")? as usize,
                invocation_id,
                idempotency_key: row.get("idempotency_key")?,
                semantics,
                tool_id: row.get("tool_id")?,
                operation_id: row.get("operation_id")?,
                status,
                checkpoint_time: row.get("checkpoint_time")?,
            })
        })())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store() -> (CheckpointStore, std::path::PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-chk-{unique}"));
        let path = dir.join("runtime_state.db");
        let store = CheckpointStore::open(&path).unwrap();
        (store, dir)
    }

    #[test]
    fn pending_then_dispatched_then_succeeded() {
        let (store, dir) = temp_store();
        let conn = store.pool.connection().unwrap();
        let task_id = Uuid::new_v4();

        CheckpointStore::write_pending(
            &conn,
            task_id,
            "agent-1",
            0,
            &SideEffectSemantics::Idempotent,
        )
        .unwrap();

        let inv_id = Uuid::new_v4();
        CheckpointStore::mark_dispatched(
            &conn,
            task_id,
            0,
            inv_id,
            "key-0",
            "filesystem",
            "write_file",
        )
        .unwrap();

        CheckpointStore::mark_succeeded(&conn, task_id, 0).unwrap();

        let cp = store.latest_for_task(task_id).unwrap().unwrap();
        assert_eq!(cp.status, CheckpointStatus::Succeeded);
        assert_eq!(cp.semantics, SideEffectSemantics::Idempotent);
        assert_eq!(cp.invocation_id, Some(inv_id));
        assert_eq!(cp.tool_id.as_deref(), Some("filesystem"));

        // Drop all open SQLite handles before deleting the directory — on
        // Windows, WAL/SHM files remain locked while a Connection is alive.
        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_unresolved_returns_dispatched_and_pending() {
        let (store, dir) = temp_store();
        let conn = store.pool.connection().unwrap();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        CheckpointStore::write_pending(&conn, t1, "agent", 0, &SideEffectSemantics::AtMostOnce)
            .unwrap();
        CheckpointStore::write_pending(&conn, t2, "agent", 0, &SideEffectSemantics::Reconcilable)
            .unwrap();
        CheckpointStore::mark_dispatched(
            &conn, t2, 0, Uuid::new_v4(), "k", "git", "commit",
        )
        .unwrap();
        // Mark t1 step 0 succeeded — should NOT appear in unresolved
        CheckpointStore::mark_succeeded(&conn, t1, 0).unwrap();

        // Add a new pending for t1 step 1
        CheckpointStore::write_pending(&conn, t1, "agent", 1, &SideEffectSemantics::Idempotent)
            .unwrap();

        let unresolved = store.list_unresolved().unwrap();
        // t2 step 0 (Dispatched) + t1 step 1 (Pending)
        assert_eq!(unresolved.len(), 2);
        let statuses: Vec<_> = unresolved.iter().map(|c| &c.status).collect();
        assert!(statuses.contains(&&CheckpointStatus::Dispatched));
        assert!(statuses.contains(&&CheckpointStatus::Pending));

        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mark_outcome_unknown_is_persisted() {
        let (store, dir) = temp_store();
        let conn = store.pool.connection().unwrap();
        let task_id = Uuid::new_v4();

        CheckpointStore::write_pending(
            &conn,
            task_id,
            "agent",
            0,
            &SideEffectSemantics::Reconcilable,
        )
        .unwrap();
        CheckpointStore::mark_dispatched(
            &conn, task_id, 0, Uuid::new_v4(), "k2", "git", "commit",
        )
        .unwrap();
        CheckpointStore::mark_outcome_unknown(&conn, task_id, 0).unwrap();

        let cp = store.latest_for_task(task_id).unwrap().unwrap();
        assert_eq!(cp.status, CheckpointStatus::OutcomeUnknown);

        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
