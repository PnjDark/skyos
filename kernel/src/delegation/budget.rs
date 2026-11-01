//! Phase 6.1C — authoritative budget accounting.
//!
//! # Why reservations exist
//!
//! A charge table alone cannot prevent a lost charge: if the provider performs
//! the work and the process dies before the charge row is written, the row that
//! would record the spend is exactly the row that never happened. The runtime
//! therefore commits to a **maximum** before the effect can occur:
//!
//! ```text
//! reserve  ->  dispatch  ->  settle
//! ```
//!
//! A reservation protects the budget before execution; a settlement records
//! measured usage after it. They are different events because the window
//! between them is where crashes lose information.
//!
//! # Exposure is supersession
//!
//! ```text
//! exposure(invocation) = sum(adjustments) + COALESCE(settlement, reservation, 0)
//! ```
//!
//! A settlement *replaces* its reservation. Adding them would double-count every
//! operation that completed normally.
//!
//! # One authority
//!
//! This ledger is authoritative for token and time exposure. Checkpoints remain
//! authoritative for execution state. Neither is derived from the other.
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::db::DatabaseConnectionPool;
use crate::tasks::store::TaskStore;

use super::DelegationKernel;

/// Which accounting event a row represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Written before dispatch. Occupies budget until superseded.
    Reservation,
    /// Written when measured usage is trustworthy. Supersedes the reservation.
    Settlement,
    /// Signed correction, appended during reconciliation. May repeat.
    Adjustment,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reservation => "Reservation",
            Self::Settlement => "Settlement",
            Self::Adjustment => "Adjustment",
        }
    }
}

impl TryFrom<&str> for EntryKind {
    type Error = BudgetError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Reservation" => Ok(Self::Reservation),
            "Settlement" => Ok(Self::Settlement),
            "Adjustment" => Ok(Self::Adjustment),
            other => Err(BudgetError::UnknownEntryKind(other.to_string())),
        }
    }
}

/// Where a duration measurement came from. Recorded so a recovery bound is never
/// mistaken for measured execution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElapsedSource {
    /// Measured between durable dispatch and durable settlement.
    Worker,
    /// Derived from dispatch time plus the dispatch timeout after a crash.
    RecoveryBound,
    /// Nothing executed.
    None,
}

impl ElapsedSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::RecoveryBound => "recovery_bound",
            Self::None => "none",
        }
    }
}

impl TryFrom<&str> for ElapsedSource {
    type Error = BudgetError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "worker" => Ok(Self::Worker),
            "recovery_bound" => Ok(Self::RecoveryBound),
            "none" => Ok(Self::None),
            other => Err(BudgetError::InvalidElapsedSource(other.to_string())),
        }
    }
}

/// One append-only accounting row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub entry_id: Uuid,
    pub task_id: Uuid,
    pub invocation_id: Uuid,
    pub kind: EntryKind,
    /// Reservation: the reserved maximum. Settlement: measured usage.
    /// Adjustment: a signed delta.
    pub tokens: i64,
    pub duration_ms: i64,
    pub elapsed_source: ElapsedSource,
    pub actor_id: String,
    pub reason: String,
    pub idempotency_key: Option<String>,
    pub recorded_at: String,
}

/// The spending limit declared for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub max_tokens: Option<i64>,
    pub max_elapsed_ms: Option<i64>,
}

/// How much budget a task (or one invocation) is currently committed to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exposure {
    pub tokens: i64,
    pub duration_ms: i64,
}

#[derive(Debug, Error)]
pub enum BudgetError {
    #[error("database error: {0}")]
    Database(#[from] crate::persistence::db::DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("task store error: {0}")]
    TaskStore(#[from] crate::tasks::store::TaskStoreError),
    #[error("unknown entry kind: '{0}'")]
    UnknownEntryKind(String),
    #[error("invalid elapsed source: '{0}'")]
    InvalidElapsedSource(String),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
    #[error("task {0} does not exist")]
    TaskNotFound(Uuid),
    #[error("task {0} has no declared budget; refusing to reserve")]
    BudgetNotDeclared(Uuid),
    #[error(
        "task {task_id} would exceed its envelope: requested {requested}, available {available}"
    )]
    BudgetExceeded {
        task_id: Uuid,
        requested: i64,
        available: i64,
    },
    #[error(
        "parent {parent} cannot allocate {requested}: only {available} of its envelope is free"
    )]
    ParentBudgetExceeded {
        parent: Uuid,
        requested: i64,
        available: i64,
    },
    #[error(
        "invocation {invocation_id} already has a {kind} entry with a different amount \
         (recorded {recorded}, requested {requested})"
    )]
    Conflict {
        invocation_id: Uuid,
        kind: &'static str,
        recorded: i64,
        requested: i64,
    },
    #[error("adjustment idempotency key '{0}' was already used with different amounts")]
    AdjustmentConflict(String),
    #[error("invalid adjustment: {0}")]
    InvalidAdjustment(String),
    #[error("invalid timestamp in ledger: {0}")]
    InvalidTimestamp(String),
    #[error("delegation error: {0}")]
    Delegation(String),
}

// ── Primitives over a caller-owned transaction ──────────────────────────────

/// Current exposure of one invocation, or `None` when it has no ledger rows.
pub fn exposure_of_invocation(
    connection: &Connection,
    invocation_id: Uuid,
) -> Result<Option<Exposure>, BudgetError> {
    let row = connection
        .query_row(
            "SELECT COUNT(*) AS rows, \
                    COALESCE(SUM(CASE WHEN entry_kind = 'Adjustment' THEN tokens ELSE 0 END), 0) \
                        + COALESCE(MAX(CASE WHEN entry_kind = 'Settlement' THEN tokens END), \
                                   MAX(CASE WHEN entry_kind = 'Reservation' THEN tokens END), 0), \
                    COALESCE(SUM(CASE WHEN entry_kind = 'Adjustment' THEN duration_ms ELSE 0 END), 0) \
                        + COALESCE(MAX(CASE WHEN entry_kind = 'Settlement' THEN duration_ms END), \
                                   MAX(CASE WHEN entry_kind = 'Reservation' THEN duration_ms END), 0) \
             FROM task_budget_ledger WHERE invocation_id = ?1",
            [invocation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;

    if row.0 == 0 {
        return Ok(None);
    }
    Ok(Some(Exposure {
        tokens: row.1,
        duration_ms: row.2,
    }))
}

/// Total exposure of a task: the sum over its invocations.
pub fn exposure_of_task(connection: &Connection, task_id: Uuid) -> Result<Exposure, BudgetError> {
    let row = connection.query_row(
        "SELECT COALESCE(SUM(per_invocation.tokens), 0), \
                COALESCE(SUM(per_invocation.duration_ms), 0) \
         FROM ( \
             SELECT invocation_id, \
                    COALESCE(SUM(CASE WHEN entry_kind = 'Adjustment' THEN tokens ELSE 0 END), 0) \
                        + COALESCE(MAX(CASE WHEN entry_kind = 'Settlement' THEN tokens END), \
                                   MAX(CASE WHEN entry_kind = 'Reservation' THEN tokens END), 0) \
                        AS tokens, \
                    COALESCE(SUM(CASE WHEN entry_kind = 'Adjustment' THEN duration_ms ELSE 0 END), 0) \
                        + COALESCE(MAX(CASE WHEN entry_kind = 'Settlement' THEN duration_ms END), \
                                   MAX(CASE WHEN entry_kind = 'Reservation' THEN duration_ms END), 0) \
                        AS duration_ms \
             FROM task_budget_ledger WHERE task_id = ?1 GROUP BY invocation_id \
         ) AS per_invocation",
        [task_id.to_string()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(Exposure {
        tokens: row.0,
        duration_ms: row.1,
    })
}

/// True when any invocation of this task holds a reservation without a
/// settlement — i.e. its usage is not yet resolved.
pub fn has_unresolved_invocations(
    connection: &Connection,
    task_id: Uuid,
) -> Result<bool, BudgetError> {
    let unresolved: i64 = connection.query_row(
        "SELECT COUNT(*) FROM task_budget_ledger r \
         WHERE r.task_id = ?1 AND r.entry_kind = 'Reservation' \
           AND NOT EXISTS ( \
               SELECT 1 FROM task_budget_ledger s \
               WHERE s.invocation_id = r.invocation_id AND s.entry_kind = 'Settlement' \
           )",
        [task_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(unresolved > 0)
}

pub fn envelope_of(
    connection: &Connection,
    task_id: Uuid,
) -> Result<Option<Envelope>, BudgetError> {
    let row = connection
        .query_row(
            "SELECT max_tokens, max_elapsed_ms FROM task_budgets WHERE task_id = ?1",
            [task_id.to_string()],
            |row| {
                Ok(Envelope {
                    max_tokens: row.get(0)?,
                    max_elapsed_ms: row.get(1)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// What a child currently occupies in its parent's envelope.
///
/// While the child is active or holds unresolved usage, its **allocation** is
/// what the parent has committed — never its allocation *and* its internal
/// usage. Once the child is terminal and fully resolved, only its settled usage
/// remains charged.
pub fn child_committed(connection: &Connection, child_task_id: Uuid) -> Result<i64, BudgetError> {
    let state: String = connection.query_row(
        "SELECT state FROM tasks WHERE task_id = ?1",
        [child_task_id.to_string()],
        |row| row.get(0),
    )?;
    let envelope = envelope_of(connection, child_task_id)?;
    let allocation = envelope.and_then(|envelope| envelope.max_tokens);
    let settled = exposure_of_task(connection, child_task_id)?.tokens;

    let terminal = matches!(state.as_str(), "Completed" | "Failed" | "Cancelled");
    let resolved = !has_unresolved_invocations(connection, child_task_id)?;

    if terminal && resolved {
        Ok(settled)
    } else {
        Ok(allocation.unwrap_or(settled))
    }
}

/// Tokens the parent has committed: children plus its own exposure.
pub fn parent_committed(connection: &Connection, parent_task_id: Uuid) -> Result<i64, BudgetError> {
    let mut committed = exposure_of_task(connection, parent_task_id)?.tokens;

    let mut statement =
        connection.prepare("SELECT task_id FROM tasks WHERE parent_task_id = ?1")?;
    let children =
        statement.query_map([parent_task_id.to_string()], |row| row.get::<_, String>(0))?;
    for child in children {
        committed += child_committed(connection, Uuid::parse_str(&child?)?)?;
    }
    Ok(committed)
}

/// Free tokens in a task's envelope. `None` means "no token envelope declared",
/// which is treated as unlimited by callers that must decide.
pub fn available_tokens(
    connection: &Connection,
    task_id: Uuid,
) -> Result<Option<i64>, BudgetError> {
    let Some(envelope) = envelope_of(connection, task_id)? else {
        return Ok(None);
    };
    let Some(max) = envelope.max_tokens else {
        return Ok(None);
    };

    let own = exposure_of_task(connection, task_id)?.tokens;
    let children = parent_committed(connection, task_id)? - own;
    Ok(Some(max - own - children))
}

/// The recovery-side elapsed bound for an uncertain invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBound {
    pub elapsed_ms: i64,
    /// True when the elapsed time was capped at the dispatch timeout.
    pub capped: bool,
    pub timeout_ms: Option<i64>,
    pub dispatched_at: String,
}

// ── Kernel surface ──────────────────────────────────────────────────────────

/// The authoritative budget ledger.
pub struct BudgetKernel {
    task_store: TaskStore,
    pool: DatabaseConnectionPool,
}

impl BudgetKernel {
    pub fn open(task_store: TaskStore) -> Result<Self, BudgetError> {
        let pool = DatabaseConnectionPool::open(task_store.database_path())?;
        let connection = pool.connection()?;
        // Recovery bounds read the checkpoint ledger, so it must exist here too.
        crate::persistence::migrations::apply_recovery_schema(&connection)?;
        crate::persistence::migrations::apply_delegation_schema(&connection)?;
        Ok(Self { task_store, pool })
    }

    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    // ── Envelope ─────────────────────────────────────────────────────────────

    pub fn declare_budget(&self, task_id: Uuid, envelope: Envelope) -> Result<(), BudgetError> {
        let connection = self.pool.connection()?;
        require_task(&connection, task_id)?;
        connection.execute(
            "INSERT INTO task_budgets (task_id, max_tokens, max_elapsed_ms, created_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(task_id) DO UPDATE SET \
                max_tokens = excluded.max_tokens, \
                max_elapsed_ms = excluded.max_elapsed_ms",
            params![
                task_id.to_string(),
                envelope.max_tokens,
                envelope.max_elapsed_ms,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ── Reservation ──────────────────────────────────────────────────────────

    /// Reserve the maximum a dispatch may spend.
    ///
    /// Must be called before the effect can occur. The transaction begins
    /// `IMMEDIATE`, so the envelope check and the insert cannot interleave with
    /// another reservation.
    pub fn reserve(
        &self,
        task_id: Uuid,
        invocation_id: Uuid,
        tokens: i64,
        timeout_ms: i64,
        actor_id: &str,
        reason: &str,
    ) -> Result<LedgerEntry, BudgetError> {
        if tokens < 0 || timeout_ms < 0 {
            return Err(BudgetError::InvalidAdjustment(
                "reservation amounts must be non-negative".to_string(),
            ));
        }

        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        require_task(&transaction, task_id)?;

        if let Some(existing) = find_entry(&transaction, invocation_id, EntryKind::Reservation)? {
            let same = existing.tokens == tokens && existing.duration_ms == timeout_ms;
            return if same {
                Ok(existing)
            } else {
                Err(BudgetError::Conflict {
                    invocation_id,
                    kind: EntryKind::Reservation.as_str(),
                    recorded: existing.tokens,
                    requested: tokens,
                })
            };
        }

        // Available = envelope − everything else this task already committed.
        let Some(envelope) = envelope_of(&transaction, task_id)? else {
            return Err(BudgetError::BudgetNotDeclared(task_id));
        };
        if let Some(max) = envelope.max_tokens {
            let own = exposure_of_task(&transaction, task_id)?.tokens;
            let children = parent_committed(&transaction, task_id)? - own;
            let available = max - own - children;
            if tokens > available {
                return Err(BudgetError::BudgetExceeded {
                    task_id,
                    requested: tokens,
                    available,
                });
            }
        }

        let entry = LedgerEntry {
            entry_id: Uuid::new_v4(),
            task_id,
            invocation_id,
            kind: EntryKind::Reservation,
            tokens,
            duration_ms: timeout_ms,
            elapsed_source: ElapsedSource::None,
            actor_id: actor_id.to_string(),
            reason: reason.to_string(),
            idempotency_key: None,
            recorded_at: Utc::now().to_rfc3339(),
        };
        insert_entry(&transaction, &entry)?;
        transaction.commit()?;
        Ok(entry)
    }

    // ── Settlement ───────────────────────────────────────────────────────────

    /// Record measured usage, superseding the reservation.
    #[allow(clippy::too_many_arguments)] // the fields are the settlement record
    pub fn settle(
        &self,
        task_id: Uuid,
        invocation_id: Uuid,
        tokens: i64,
        duration_ms: i64,
        source: ElapsedSource,
        actor_id: &str,
        reason: &str,
    ) -> Result<LedgerEntry, BudgetError> {
        if tokens < 0 || duration_ms < 0 {
            return Err(BudgetError::InvalidAdjustment(
                "settlement amounts must be non-negative".to_string(),
            ));
        }

        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task(&transaction, task_id)?;

        if let Some(existing) = find_entry(&transaction, invocation_id, EntryKind::Settlement)? {
            let same = existing.tokens == tokens && existing.duration_ms == duration_ms;
            return if same {
                Ok(existing)
            } else {
                Err(BudgetError::Conflict {
                    invocation_id,
                    kind: EntryKind::Settlement.as_str(),
                    recorded: existing.tokens,
                    requested: tokens,
                })
            };
        }

        let entry = LedgerEntry {
            entry_id: Uuid::new_v4(),
            task_id,
            invocation_id,
            kind: EntryKind::Settlement,
            tokens,
            duration_ms,
            elapsed_source: source,
            actor_id: actor_id.to_string(),
            reason: reason.to_string(),
            idempotency_key: None,
            recorded_at: Utc::now().to_rfc3339(),
        };
        insert_entry(&transaction, &entry)?;
        transaction.commit()?;
        Ok(entry)
    }

    /// Settle an invocation that provably never dispatched (a `Pending`
    /// checkpoint): zero usage, which releases the reservation.
    pub fn settle_never_dispatched(
        &self,
        task_id: Uuid,
        invocation_id: Uuid,
        actor_id: &str,
    ) -> Result<LedgerEntry, BudgetError> {
        self.settle(
            task_id,
            invocation_id,
            0,
            0,
            ElapsedSource::None,
            actor_id,
            "checkpoint was pending: the tool provably never ran",
        )
    }

    // ── Adjustment ───────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn adjust(
        &self,
        task_id: Uuid,
        invocation_id: Uuid,
        tokens_delta: i64,
        duration_delta_ms: i64,
        actor_id: &str,
        reason: &str,
        idempotency_key: &str,
    ) -> Result<LedgerEntry, BudgetError> {
        if idempotency_key.trim().is_empty() {
            return Err(BudgetError::InvalidAdjustment(
                "an adjustment requires a non-empty idempotency key".to_string(),
            ));
        }

        let mut connection = self.pool.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task(&transaction, task_id)?;

        let existing = transaction
            .query_row(
                "SELECT entry_id, task_id, invocation_id, entry_kind, tokens, duration_ms, \
                        elapsed_source, actor_id, reason, idempotency_key, recorded_at \
                 FROM task_budget_ledger \
                 WHERE entry_kind = 'Adjustment' AND idempotency_key = ?1",
                [idempotency_key],
                map_entry,
            )
            .optional()?;

        if let Some(existing) = existing {
            let same = existing.tokens == tokens_delta
                && existing.duration_ms == duration_delta_ms
                && existing.task_id == task_id
                && existing.invocation_id == invocation_id;
            return if same {
                Ok(existing)
            } else {
                Err(BudgetError::AdjustmentConflict(idempotency_key.to_string()))
            };
        }

        let entry = LedgerEntry {
            entry_id: Uuid::new_v4(),
            task_id,
            invocation_id,
            kind: EntryKind::Adjustment,
            tokens: tokens_delta,
            duration_ms: duration_delta_ms,
            elapsed_source: ElapsedSource::RecoveryBound,
            actor_id: actor_id.to_string(),
            reason: reason.to_string(),
            idempotency_key: Some(idempotency_key.to_string()),
            recorded_at: Utc::now().to_rfc3339(),
        };
        insert_entry(&transaction, &entry)?;
        transaction.commit()?;
        Ok(entry)
    }

    // ── Reads ────────────────────────────────────────────────────────────────

    pub fn exposure_of_invocation(
        &self,
        invocation_id: Uuid,
    ) -> Result<Option<Exposure>, BudgetError> {
        let connection = self.pool.connection()?;
        exposure_of_invocation(&connection, invocation_id)
    }

    pub fn exposure_of_task(&self, task_id: Uuid) -> Result<Exposure, BudgetError> {
        let connection = self.pool.connection()?;
        exposure_of_task(&connection, task_id)
    }

    pub fn entries_for_invocation(
        &self,
        invocation_id: Uuid,
    ) -> Result<Vec<LedgerEntry>, BudgetError> {
        let connection = self.pool.connection()?;
        let mut statement = connection.prepare(
            "SELECT entry_id, task_id, invocation_id, entry_kind, tokens, duration_ms, \
                    elapsed_source, actor_id, reason, idempotency_key, recorded_at \
             FROM task_budget_ledger WHERE invocation_id = ?1 ORDER BY recorded_at ASC, rowid ASC",
        )?;
        let rows = statement.query_map([invocation_id.to_string()], map_entry)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn available_tokens(&self, task_id: Uuid) -> Result<Option<i64>, BudgetError> {
        let connection = self.pool.connection()?;
        available_tokens(&connection, task_id)
    }

    /// Conservative elapsed bound for an invocation whose outcome is unknown.
    ///
    /// Both inputs are durable: the dispatch instant comes from the
    /// `Dispatched` checkpoint row, and the timeout comes from the reservation
    /// written before dispatch. Neither is read from current configuration.
    pub fn recovery_bound(
        &self,
        invocation_id: Uuid,
    ) -> Result<Option<RecoveryBound>, BudgetError> {
        let connection = self.pool.connection()?;

        let dispatched_at: Option<String> = connection
            .query_row(
                "SELECT checkpoint_time FROM task_checkpoints WHERE invocation_id = ?1",
                [invocation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(dispatched_at) = dispatched_at else {
            return Ok(None);
        };
        let dispatched = DateTime::parse_from_rfc3339(&dispatched_at)
            .map_err(|_| BudgetError::InvalidTimestamp(dispatched_at.clone()))?
            .with_timezone(&Utc);

        let timeout_ms = find_entry(&connection, invocation_id, EntryKind::Reservation)?
            .map(|entry| entry.duration_ms);
        let elapsed_ms = (Utc::now() - dispatched).num_milliseconds().max(0);

        let (elapsed_ms, capped) = match timeout_ms {
            Some(timeout) if timeout > 0 && elapsed_ms > timeout => (timeout, true),
            _ => (elapsed_ms, false),
        };

        Ok(Some(RecoveryBound {
            elapsed_ms,
            capped,
            timeout_ms,
            dispatched_at,
        }))
    }
}

// ── Internals ───────────────────────────────────────────────────────────────

fn require_task(connection: &Connection, task_id: Uuid) -> Result<(), BudgetError> {
    let exists: i64 = connection.query_row(
        "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
        [task_id.to_string()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(BudgetError::TaskNotFound(task_id));
    }
    Ok(())
}

fn find_entry(
    connection: &Connection,
    invocation_id: Uuid,
    kind: EntryKind,
) -> Result<Option<LedgerEntry>, BudgetError> {
    let entry = connection
        .query_row(
            "SELECT entry_id, task_id, invocation_id, entry_kind, tokens, duration_ms, \
                    elapsed_source, actor_id, reason, idempotency_key, recorded_at \
             FROM task_budget_ledger WHERE invocation_id = ?1 AND entry_kind = ?2",
            params![invocation_id.to_string(), kind.as_str()],
            map_entry,
        )
        .optional()?;
    Ok(entry)
}

fn insert_entry(connection: &Connection, entry: &LedgerEntry) -> Result<(), BudgetError> {
    connection.execute(
        "INSERT INTO task_budget_ledger \
         (entry_id, task_id, invocation_id, entry_kind, tokens, duration_ms, elapsed_source, \
          actor_id, reason, idempotency_key, recorded_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            entry.entry_id.to_string(),
            entry.task_id.to_string(),
            entry.invocation_id.to_string(),
            entry.kind.as_str(),
            entry.tokens,
            entry.duration_ms,
            entry.elapsed_source.as_str(),
            entry.actor_id,
            entry.reason,
            entry.idempotency_key,
            entry.recorded_at,
        ],
    )?;
    Ok(())
}

fn map_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerEntry> {
    let kind: String = row.get(3)?;
    let source: String = row.get(6)?;
    Ok(LedgerEntry {
        entry_id: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        task_id: Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        invocation_id: Uuid::parse_str(&row.get::<_, String>(2)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        kind: EntryKind::try_from(kind.as_str()).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        tokens: row.get(4)?,
        duration_ms: row.get(5)?,
        elapsed_source: ElapsedSource::try_from(source.as_str()).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        actor_id: row.get(7)?,
        reason: row.get(8)?,
        idempotency_key: row.get(9)?,
        recorded_at: row.get(10)?,
    })
}

/// Allocate a child's envelope from its parent, inside the caller's transaction.
///
/// Used by [`DelegationKernel::create_child_with_budget`] so the child row, its
/// dependency edges and its allocation commit or roll back together.
pub(crate) fn allocate_child_in_transaction(
    connection: &Connection,
    parent_task_id: Uuid,
    child_task_id: Uuid,
    allocation_tokens: i64,
) -> Result<(), BudgetError> {
    if allocation_tokens < 0 {
        return Err(BudgetError::InvalidAdjustment(
            "child allocation must be non-negative".to_string(),
        ));
    }

    let Some(parent_envelope) = envelope_of(connection, parent_task_id)? else {
        return Err(BudgetError::BudgetNotDeclared(parent_task_id));
    };
    let Some(max) = parent_envelope.max_tokens else {
        return Err(BudgetError::BudgetNotDeclared(parent_task_id));
    };

    let own = exposure_of_task(connection, parent_task_id)?.tokens;
    let committed_children = parent_committed(connection, parent_task_id)? - own;
    let available = max - own - committed_children;

    if allocation_tokens > available {
        return Err(BudgetError::ParentBudgetExceeded {
            parent: parent_task_id,
            requested: allocation_tokens,
            available,
        });
    }

    connection.execute(
        "INSERT INTO task_budgets (task_id, max_tokens, max_elapsed_ms, created_at) \
         VALUES (?1, ?2, NULL, ?3)",
        params![
            child_task_id.to_string(),
            allocation_tokens,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Convenience wrapper so callers can allocate without importing the primitive.
impl DelegationKernel {
    /// Create a child whose envelope is reserved from `parent` in the same
    /// transaction. Rejects the creation if the parent cannot afford it.
    pub fn create_child_with_budget(
        &self,
        parent_task_id: Uuid,
        spec: super::ChildTaskSpec,
        allocation_tokens: i64,
    ) -> Result<Uuid, BudgetError> {
        match self.create_child_inner(parent_task_id, spec, Some(allocation_tokens)) {
            Ok(task_id) => Ok(task_id),
            // Preserve the budget verdict instead of flattening it to a string.
            Err(super::DelegationError::Budget(error)) => Err(error),
            Err(other) => Err(BudgetError::Delegation(other.to_string())),
        }
    }
}
