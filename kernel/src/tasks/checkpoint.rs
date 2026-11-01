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
///   (status = `Pending`).
/// - **`mark_succeeded`** / **`mark_failed`** / **`mark_outcome_unknown`**
///   must be called *after* the result is observed, inside the same commit.
/// - Recovery uses `list_unresolved` to find rows with status `Dispatched`
///   or `Pending` after a crash.
///
/// # Epistemic rule
///
/// A checkpoint records what the *runtime knows* about an invocation.  It is
/// never evidence about the external world by itself: a `Dispatched` row means
/// "an attempt may have happened", not "the attempt failed".  Recovery must
/// therefore never convert `Dispatched` directly into a retryable state.
use std::path::Path;

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::{
    db::{DatabaseConnectionPool, DatabaseError},
    migrations::apply_recovery_schema,
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
    /// Recovery approved a retry under a fresh authorization.
    RetryReady,
}

impl CheckpointStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Dispatched => "Dispatched",
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::OutcomeUnknown => "OutcomeUnknown",
            Self::RetryReady => "RetryReady",
        }
    }

    /// True when the row no longer blocks a recovery pass.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::OutcomeUnknown)
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
            "RetryReady" => Ok(Self::RetryReady),
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
    /// Canonical-argument SHA-256 that `idempotency_key` was derived from.
    pub argument_fingerprint: Option<String>,
    pub semantics: SideEffectSemantics,
    pub tool_id: Option<String>,
    pub operation_id: Option<String>,
    pub status: CheckpointStatus,
    pub checkpoint_time: String,
}

/// Identity and operation metadata fixed before a tool invocation is dispatched.
#[derive(Debug, Clone)]
pub struct CheckpointInvocation {
    pub invocation_id: Uuid,
    pub idempotency_key: String,
    pub argument_fingerprint: String,
    pub semantics: SideEffectSemantics,
    pub tool_id: String,
    pub operation_id: String,
}

/// Result of asking the ledger whether a proposed idempotency key may proceed.
///
/// The runtime never treats a reused key as "probably the same request": a key
/// that was minted from different arguments is an explicit conflict.
#[derive(Debug, Clone)]
pub enum IdempotencyLookup {
    /// The key has never been used; a fresh invocation may proceed.
    Unused,
    /// Same key, same arguments, and the recorded attempt already terminated.
    /// The caller may reuse the recorded outcome instead of re-executing.
    Replayable(Box<TaskCheckpoint>),
    /// Same key, same arguments, but the recorded attempt has not terminated.
    /// The caller must not dispatch a second physical attempt.
    InFlight(Box<TaskCheckpoint>),
    /// Same key, different arguments.  Neither reuse nor dispatch is permitted.
    Conflict {
        recorded_step: usize,
        recorded_fingerprint: Option<String>,
    },
}

impl IdempotencyLookup {
    /// True when the proposal diverges from the recorded intent of this key.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }
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
    #[error(
        "checkpoint {task_id}/{step_number} was not in an expected state for transition to {status}"
    )]
    InvalidTransition {
        task_id: Uuid,
        step_number: usize,
        status: String,
    },
    #[error(
        "idempotency key '{key}' was already recorded for step {recorded_step} with different arguments"
    )]
    IdempotencyConflict { key: String, recorded_step: usize },
    #[error("checkpoint JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

// ── Idempotency key ──────────────────────────────────────────────────────────

/// Version tag mixed into every derived key.  Bumping this invalidates keys
/// minted by older runtimes instead of silently colliding with them.
const IDEMPOTENCY_KEY_VERSION: &str = "skyos-idem-v1";

/// Compute the canonical-argument fingerprint for one tool invocation.
///
/// Object keys are sorted recursively, so two proposals that differ only in
/// JSON member ordering produce the same fingerprint, while any change to a
/// value produces a different one.
pub fn compute_argument_fingerprint(arguments: &serde_json::Value) -> String {
    let canonical = canonical_json(arguments);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Compute a stable, collision-resistant idempotency key for one agent step.
///
/// The key is SHA-256 over length-prefixed fields:
///   task_id | step_number | tool_id | operation_id | argument_fingerprint
///
/// Length prefixing makes the encoding unambiguous: a tool named `a/commit`
/// can never produce the same byte stream as tool `a` with operation
/// `/commit`.  Including the fingerprint means two proposals that share the
/// same task, step, tool, and operation but differ in *any* argument value
/// produce distinct keys, preventing silent result reuse when the agent
/// revises its proposal mid-task.
pub fn compute_idempotency_key(
    task_id: &Uuid,
    step_number: usize,
    tool_id: &str,
    operation_id: &str,
    arguments: &serde_json::Value,
) -> String {
    let fingerprint = compute_argument_fingerprint(arguments);
    let task_id = task_id.to_string();
    let step_number = step_number.to_string();
    let fields: [&str; 6] = [
        IDEMPOTENCY_KEY_VERSION,
        &task_id,
        &step_number,
        tool_id,
        operation_id,
        &fingerprint,
    ];

    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Produce a deterministic JSON string with object keys sorted recursively.
///
/// # Canonicalization contract (`skyos-canonical-json-v1`)
///
/// * **Object keys** are ordered by their UTF-8 bytes (`str` ordering), so
///   member order never affects the fingerprint.
/// * **Numbers** are normalized: integral values are rendered as integers, so
///   `1`, `1.0` and `1e0` are the same argument.  Non-integral values use the
///   shortest round-trippable decimal form, which is locale-independent and
///   stable across supported platforms.
/// * **Strings** are escaped by `serde_json`, so the fingerprint is computed on
///   the parsed value, never on the caller's original byte encoding.
/// * **`null` is distinct from an omitted key.**  `{"a": null}` and `{}` are
///   different proposals to a tool and fingerprint differently.
/// * **Array order is preserved** — order is meaningful in a proposal.
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
            let inner: Vec<String> = pairs
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("object keys always serialize"),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(number) => canonical_number(number),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("strings always serialize")
        }
    }
}

fn canonical_number(number: &serde_json::Number) -> String {
    if let Some(integer) = number.as_i64() {
        return integer.to_string();
    }
    if let Some(integer) = number.as_u64() {
        return integer.to_string();
    }

    let value = number
        .as_f64()
        .expect("serde_json numbers are i64, u64, or f64");

    // Integral floats collapse onto the integer form: 1.0 and 1 are the same
    // argument to a tool.  The bound keeps the conversion exact.
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        return (value as i64).to_string();
    }

    // `Debug` for f64 is the shortest round-trippable representation.
    format!("{value:?}")
}

// ── Store ─────────────────────────────────────────────────────────────────────

const CHECKPOINT_COLUMNS: &str = "task_id, agent_id, step_number, invocation_id, idempotency_key, \
     argument_fingerprint, semantics, tool_id, operation_id, status, checkpoint_time";

/// Kernel-owned durable execution ledger.
///
/// All mutating methods that accept a `&Connection` are designed to be called
/// from inside an existing transaction so the checkpoint write is atomic with
/// the task-state update and the event emission.
#[derive(Clone)]
pub struct CheckpointStore {
    pool: DatabaseConnectionPool,
}

impl CheckpointStore {
    /// Open (or create) the checkpoint store at `path`.
    ///
    /// Applies `M4_CHECKPOINT_SCHEMA` on the shared `runtime_state.db` — the
    /// same file used by `TaskStore` and `EventBus`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CheckpointError> {
        let pool = DatabaseConnectionPool::open(path)?;
        let conn = pool.connection()?;
        apply_recovery_schema(&conn)?;
        Ok(Self { pool })
    }

    /// Open a new `rusqlite::Connection` to the checkpoint database.
    ///
    /// Use this when you need to perform a checkpoint write atomically with
    /// other operations (e.g. inside a shared transaction).  Each call returns
    /// a fresh connection — callers must not hold multiple connections open
    /// simultaneously under WAL mode without coordinating.
    pub fn connection(&self) -> Result<rusqlite::Connection, CheckpointError> {
        Ok(self.pool.connection()?)
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
            "INSERT INTO task_checkpoints \
             (task_id, agent_id, step_number, invocation_id, idempotency_key, \
              argument_fingerprint, semantics, tool_id, operation_id, status, checkpoint_time) \
             VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, NULL, NULL, 'Pending', ?5)",
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

    /// Write a pending step with its invocation and idempotency identities
    /// already fixed before dispatch.
    pub fn write_pending_invocation(
        conn: &Connection,
        task_id: Uuid,
        agent_id: &str,
        step_number: usize,
        invocation: &CheckpointInvocation,
    ) -> Result<(), CheckpointError> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO task_checkpoints \
             (task_id, agent_id, step_number, invocation_id, idempotency_key, \
              argument_fingerprint, semantics, tool_id, operation_id, status, checkpoint_time) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'Pending', ?10)",
            rusqlite::params![
                task_id.to_string(),
                agent_id,
                step_number as i64,
                invocation.invocation_id.to_string(),
                &invocation.idempotency_key,
                &invocation.argument_fingerprint,
                invocation.semantics.as_str(),
                &invocation.tool_id,
                &invocation.operation_id,
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
        let changed = conn.execute(
            "UPDATE task_checkpoints \
             SET invocation_id = ?1, idempotency_key = ?2, tool_id = ?3, operation_id = ?4, \
                 status = 'Dispatched', checkpoint_time = ?5 \
             WHERE task_id = ?6 AND step_number = ?7 \
               AND status IN ('Pending', 'RetryReady')",
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
        if changed != 1 {
            return Err(CheckpointError::InvalidTransition {
                task_id,
                step_number,
                status: CheckpointStatus::Dispatched.as_str().to_string(),
            });
        }
        Ok(())
    }

    /// Mark a `Pending` checkpoint — which proves dispatch never occurred —
    /// ready for a *semantically* safe retry.
    ///
    /// This does **not** authorize execution.  A `RetryReady` row still needs a
    /// fresh grant issued by `RecoveryAuthorizer` before it may be dispatched.
    pub fn mark_retry_ready_from_pending(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(
            conn,
            task_id,
            step_number,
            CheckpointStatus::RetryReady,
            "'Pending'",
        )
    }

    /// Promote an `OutcomeUnknown` checkpoint to `RetryReady` after physical
    /// reconciliation proved the previous attempt left no trace.
    ///
    /// Only the recovery reconciler may call this, and only with evidence.
    pub fn mark_authorized_retry_ready(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(
            conn,
            task_id,
            step_number,
            CheckpointStatus::RetryReady,
            "'OutcomeUnknown'",
        )
    }

    /// Mark a dispatched (or reconciled) invocation `Succeeded`.
    pub fn mark_succeeded(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(
            conn,
            task_id,
            step_number,
            CheckpointStatus::Succeeded,
            "'Dispatched', 'OutcomeUnknown'",
        )
    }

    /// Mark a dispatched invocation `Failed`.
    pub fn mark_failed(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(
            conn,
            task_id,
            step_number,
            CheckpointStatus::Failed,
            "'Pending', 'Dispatched', 'OutcomeUnknown'",
        )
    }

    /// Mark a dispatched invocation `OutcomeUnknown`.
    ///
    /// Called by the executor when a result or its audit could not be
    /// established, and by the recovery engine for every interrupted
    /// `Dispatched` (or `Pending`) row it finds on startup.
    pub fn mark_outcome_unknown(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<(), CheckpointError> {
        Self::set_status(
            conn,
            task_id,
            step_number,
            CheckpointStatus::OutcomeUnknown,
            "'Pending', 'Dispatched'",
        )
    }

    fn set_status(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
        status: CheckpointStatus,
        allowed_from: &str,
    ) -> Result<(), CheckpointError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "UPDATE task_checkpoints SET status = ?1, checkpoint_time = ?2 \
             WHERE task_id = ?3 AND step_number = ?4 AND status IN ({allowed_from})"
        );
        let changed = conn.execute(
            &sql,
            rusqlite::params![
                status.as_str(),
                now,
                task_id.to_string(),
                step_number as i64,
            ],
        )?;
        if changed != 1 {
            return Err(CheckpointError::InvalidTransition {
                task_id,
                step_number,
                status: status.as_str().to_string(),
            });
        }
        Ok(())
    }

    // ── Idempotency conflict detection ────────────────────────────────────────

    /// Decide whether a proposal may proceed, using the recorded fingerprint.
    ///
    /// A key derived from different arguments is always a conflict; it is never
    /// resolved by returning a previous result.
    pub fn lookup_idempotency(
        conn: &Connection,
        idempotency_key: &str,
        argument_fingerprint: &str,
    ) -> Result<IdempotencyLookup, CheckpointError> {
        let recorded = Self::find_by_idempotency_key(conn, idempotency_key)?;
        let Some(recorded) = recorded else {
            return Ok(IdempotencyLookup::Unused);
        };

        match recorded.argument_fingerprint.as_deref() {
            Some(recorded_fingerprint) if recorded_fingerprint == argument_fingerprint => {
                if recorded.status.is_terminal() {
                    Ok(IdempotencyLookup::Replayable(Box::new(recorded)))
                } else {
                    Ok(IdempotencyLookup::InFlight(Box::new(recorded)))
                }
            }
            recorded_fingerprint => Ok(IdempotencyLookup::Conflict {
                recorded_step: recorded.step_number,
                recorded_fingerprint: recorded_fingerprint.map(str::to_owned),
            }),
        }
    }

    /// Return the row that owns `idempotency_key`, if any.
    pub fn find_by_idempotency_key(
        conn: &Connection,
        idempotency_key: &str,
    ) -> Result<Option<TaskCheckpoint>, CheckpointError> {
        let row = conn
            .query_row(
                &format!(
                    "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
                     WHERE idempotency_key = ?1 ORDER BY step_number ASC LIMIT 1"
                ),
                [idempotency_key],
                Self::map_row,
            )
            .optional()?;
        row.transpose()
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    /// Return all checkpoints for `task_id`, ordered by step number ascending.
    pub fn list_for_task(&self, task_id: Uuid) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        self.query_checkpoints(&conn, task_id)
    }

    /// Return every checkpoint whose status is `Dispatched` or `Pending`
    /// across all tasks.  Used by the recovery engine on startup.
    pub fn list_unresolved(&self) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
             WHERE status IN ('Pending', 'Dispatched') \
             ORDER BY task_id, step_number ASC"
        ))?;
        self.collect_rows(&mut stmt, [])
    }

    /// Return checkpoints explicitly approved for safe re-dispatch.
    pub fn list_retry_ready(&self) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
             WHERE status = 'RetryReady' \
             ORDER BY task_id, step_number ASC"
        ))?;
        self.collect_rows(&mut stmt, [])
    }

    /// Return checkpoints whose outcome is unknown for `task_id`.
    pub fn list_outcome_unknown(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
             WHERE task_id = ?1 AND status = 'OutcomeUnknown' \
             ORDER BY step_number ASC"
        ))?;
        self.collect_rows(&mut stmt, rusqlite::params![task_id.to_string()])
    }

    /// Return the checkpoint for exactly `(task_id, step_number)`.
    pub fn get(
        &self,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<Option<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        Self::get_with_connection(&conn, task_id, step_number)
    }

    /// Return the checkpoint for exactly `(task_id, step_number)` using a
    /// caller-owned connection (so it can join an in-flight transaction).
    pub fn get_with_connection(
        conn: &Connection,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<Option<TaskCheckpoint>, CheckpointError> {
        let row = conn
            .query_row(
                &format!(
                    "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
                     WHERE task_id = ?1 AND step_number = ?2"
                ),
                rusqlite::params![task_id.to_string(), step_number as i64],
                Self::map_row,
            )
            .optional()?;
        row.transpose()
    }

    /// Return the most recent checkpoint for `task_id` (highest step_number).
    pub fn latest_for_task(
        &self,
        task_id: Uuid,
    ) -> Result<Option<TaskCheckpoint>, CheckpointError> {
        let conn = self.pool.connection()?;
        let row = conn
            .query_row(
                &format!(
                    "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
                     WHERE task_id = ?1 ORDER BY step_number DESC LIMIT 1"
                ),
                [task_id.to_string()],
                Self::map_row,
            )
            .optional()?;
        row.transpose()
    }

    // ── Private row mapping ───────────────────────────────────────────────────

    fn query_checkpoints(
        &self,
        conn: &Connection,
        task_id: Uuid,
    ) -> Result<Vec<TaskCheckpoint>, CheckpointError> {
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM task_checkpoints \
             WHERE task_id = ?1 ORDER BY step_number ASC"
        ))?;
        self.collect_rows(&mut stmt, rusqlite::params![task_id.to_string()])
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

    fn map_row(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<Result<TaskCheckpoint, CheckpointError>> {
        let task_id_str: String = row.get("task_id")?;
        let invocation_str: Option<String> = row.get("invocation_id")?;
        let semantics_str: String = row.get("semantics")?;
        let status_str: String = row.get("status")?;

        Ok((|| -> Result<TaskCheckpoint, CheckpointError> {
            let task_id = Uuid::parse_str(&task_id_str)?;
            let invocation_id = invocation_str.map(|s| Uuid::parse_str(&s)).transpose()?;
            let semantics = SideEffectSemantics::try_from(semantics_str.as_str())?;
            let status = CheckpointStatus::try_from(status_str.as_str())?;

            Ok(TaskCheckpoint {
                task_id,
                agent_id: row.get("agent_id")?,
                step_number: row.get::<_, i64>("step_number")? as usize,
                invocation_id,
                idempotency_key: row.get("idempotency_key")?,
                argument_fingerprint: row.get("argument_fingerprint")?,
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

    fn invocation(message: &str) -> (CheckpointInvocation, String) {
        let arguments = serde_json::json!({ "message": message });
        let key = compute_idempotency_key(&Uuid::nil(), 0, "git", "commit", &arguments);
        (
            CheckpointInvocation {
                invocation_id: Uuid::new_v4(),
                idempotency_key: key.clone(),
                argument_fingerprint: compute_argument_fingerprint(&arguments),
                semantics: SideEffectSemantics::Reconcilable,
                tool_id: "git".into(),
                operation_id: "commit".into(),
            },
            key,
        )
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
        CheckpointStore::mark_dispatched(&conn, t2, 0, Uuid::new_v4(), "k", "git", "commit")
            .unwrap();
        // Mark t1 step 0 succeeded — should NOT appear in unresolved
        CheckpointStore::mark_dispatched(
            &conn,
            t1,
            0,
            Uuid::new_v4(),
            "k0",
            "filesystem",
            "read_file",
        )
        .unwrap();
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
        CheckpointStore::mark_dispatched(&conn, task_id, 0, Uuid::new_v4(), "k2", "git", "commit")
            .unwrap();
        CheckpointStore::mark_outcome_unknown(&conn, task_id, 0).unwrap();

        let cp = store.latest_for_task(task_id).unwrap().unwrap();
        assert_eq!(cp.status, CheckpointStatus::OutcomeUnknown);

        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    // ── Idempotency fingerprinting ───────────────────────────────────────────

    #[test]
    fn different_commit_messages_produce_different_idempotency_keys() {
        let task_id = Uuid::new_v4();
        let first = serde_json::json!({ "message": "Initial implementation" });
        let second = serde_json::json!({ "message": "Fix authentication" });

        let key_a = compute_idempotency_key(&task_id, 0, "git", "commit", &first);
        let key_b = compute_idempotency_key(&task_id, 0, "git", "commit", &second);

        assert_ne!(
            key_a, key_b,
            "a revised argument payload must never reuse the previous idempotency key"
        );
    }

    #[test]
    fn argument_order_does_not_change_the_fingerprint() {
        let left: serde_json::Value =
            serde_json::from_str(r#"{"a": 1, "b": {"x": true, "y": "z"}}"#).unwrap();
        let right: serde_json::Value =
            serde_json::from_str(r#"{"b": {"y": "z", "x": true}, "a": 1}"#).unwrap();

        assert_eq!(
            compute_argument_fingerprint(&left),
            compute_argument_fingerprint(&right)
        );
    }

    #[test]
    fn integral_numbers_are_canonicalized() {
        let integer: serde_json::Value = serde_json::from_str(r#"{"count": 1}"#).unwrap();
        let float: serde_json::Value = serde_json::from_str(r#"{"count": 1.0}"#).unwrap();
        let exponent: serde_json::Value = serde_json::from_str(r#"{"count": 1e0}"#).unwrap();

        assert_eq!(
            compute_argument_fingerprint(&integer),
            compute_argument_fingerprint(&float),
            "1 and 1.0 are the same argument to a tool"
        );
        assert_eq!(
            compute_argument_fingerprint(&integer),
            compute_argument_fingerprint(&exponent)
        );

        let fractional: serde_json::Value = serde_json::from_str(r#"{"count": 1.5}"#).unwrap();
        assert_ne!(
            compute_argument_fingerprint(&integer),
            compute_argument_fingerprint(&fractional)
        );
    }

    #[test]
    fn null_and_omitted_fields_are_different_proposals() {
        let with_null: serde_json::Value = serde_json::from_str(r#"{"a": null}"#).unwrap();
        let omitted: serde_json::Value = serde_json::from_str("{}").unwrap();

        assert_ne!(
            compute_argument_fingerprint(&with_null),
            compute_argument_fingerprint(&omitted),
            "clearing a field is not the same operation as never setting it"
        );
    }

    #[test]
    fn string_escaping_normalizes_to_the_parsed_value() {
        let escaped: serde_json::Value = serde_json::from_str(r#"{"msg": "caf\u00e9"}"#).unwrap();
        let literal: serde_json::Value = serde_json::from_str("{\"msg\": \"caf\u{e9}\"}").unwrap();

        assert_eq!(
            compute_argument_fingerprint(&escaped),
            compute_argument_fingerprint(&literal),
            "the fingerprint is computed on the parsed value, not the caller's byte encoding"
        );
    }

    #[test]
    fn identical_key_with_different_arguments_is_a_conflict_not_a_replay() {
        let (store, dir) = temp_store();
        let conn = store.pool.connection().unwrap();
        let task_id = Uuid::new_v4();
        let (inv, key) = invocation("Initial implementation");
        let fingerprint = inv.argument_fingerprint.clone();

        CheckpointStore::write_pending_invocation(&conn, task_id, "agent", 0, &inv).unwrap();

        // Same key, same arguments, still unresolved → in flight, not replayable.
        let same = CheckpointStore::lookup_idempotency(&conn, &key, &fingerprint).unwrap();
        assert!(matches!(same, IdempotencyLookup::InFlight(_)));

        // Same key, different arguments → conflict.
        let other = compute_argument_fingerprint(&serde_json::json!({ "message": "Fix auth" }));
        let conflict = CheckpointStore::lookup_idempotency(&conn, &key, &other).unwrap();
        assert!(conflict.is_conflict());

        CheckpointStore::mark_dispatched(
            &conn,
            task_id,
            0,
            inv.invocation_id,
            &key,
            "git",
            "commit",
        )
        .unwrap();
        CheckpointStore::mark_succeeded(&conn, task_id, 0).unwrap();

        let replay = CheckpointStore::lookup_idempotency(&conn, &key, &fingerprint).unwrap();
        assert!(matches!(replay, IdempotencyLookup::Replayable(_)));

        let unused =
            CheckpointStore::lookup_idempotency(&conn, "never-used", &fingerprint).unwrap();
        assert!(matches!(unused, IdempotencyLookup::Unused));

        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dispatched_rows_cannot_be_marked_retry_ready_without_evidence() {
        let (store, dir) = temp_store();
        let conn = store.pool.connection().unwrap();
        let task_id = Uuid::new_v4();

        CheckpointStore::write_pending(
            &conn,
            task_id,
            "agent",
            0,
            &SideEffectSemantics::Idempotent,
        )
        .unwrap();
        CheckpointStore::mark_dispatched(&conn, task_id, 0, Uuid::new_v4(), "k", "git", "commit")
            .unwrap();

        assert!(
            CheckpointStore::mark_retry_ready_from_pending(&conn, task_id, 0).is_err(),
            "a dispatched attempt must never become retryable without reconciliation"
        );

        CheckpointStore::mark_outcome_unknown(&conn, task_id, 0).unwrap();
        CheckpointStore::mark_authorized_retry_ready(&conn, task_id, 0).unwrap();
        assert_eq!(
            store.latest_for_task(task_id).unwrap().unwrap().status,
            CheckpointStatus::RetryReady
        );

        drop(conn);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
