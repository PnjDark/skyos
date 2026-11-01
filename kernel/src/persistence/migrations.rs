pub const M1_INITIAL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_task_id ON events(task_id);
"#;

pub const M2_TASKS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    priority INTEGER NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
"#;

/// M8 — Delegation DAG (Phase 6.1A/6.1B).
///
/// `parent_task_id`, `assigned_agent_id` and `objective` extend the existing
/// task row rather than duplicating it in a second `delegated_tasks` table: the
/// task row *is* the delegation record, and two sources of truth for one task
/// would drift.
///
/// `task_dependencies` holds the edges. The `dependent -> prerequisite`
/// direction is fixed: an edge means "dependent may not run until prerequisite
/// is Completed".
pub const M8_DELEGATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_dependencies (
    dependent_task_id    TEXT NOT NULL,
    prerequisite_task_id TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    PRIMARY KEY (dependent_task_id, prerequisite_task_id),
    FOREIGN KEY (dependent_task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (prerequisite_task_id) REFERENCES tasks(task_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_task_dependencies_prereq
    ON task_dependencies(prerequisite_task_id);
"#;

/// Additive columns for M8, applied with `ALTER TABLE` on existing databases.
pub const M8_DELEGATION_COLUMNS: [(&str, &str); 3] = [
    ("parent_task_id", "TEXT"),
    ("assigned_agent_id", "TEXT"),
    ("objective", "TEXT"),
];

/// M9 — Budget accounting (Phase 6.1C).
///
/// Two tables, one authority:
///
/// * `task_budgets` holds the envelope a task may spend within.
/// * `task_budget_ledger` is the append-only accounting record. A reservation
///   protects the budget *before* execution; a settlement records measured
///   usage *after* it. They are never the same event, because the window
///   between them is exactly where a crash loses the charge.
///
/// Exposure is **supersession**, not addition: a settlement replaces its
/// reservation, and adjustments are signed deltas applied on top.
pub const M9_BUDGET_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_budgets (
    task_id        TEXT PRIMARY KEY,
    max_tokens     INTEGER,
    max_elapsed_ms INTEGER,
    created_at     TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS task_budget_ledger (
    entry_id            TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL,
    invocation_id       TEXT NOT NULL,
    entry_kind          TEXT NOT NULL
                        CHECK (entry_kind IN ('Reservation', 'Settlement', 'Adjustment')),
    tokens              INTEGER NOT NULL DEFAULT 0,
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    elapsed_source      TEXT NOT NULL DEFAULT 'none',
    actor_id            TEXT NOT NULL,
    reason              TEXT NOT NULL,
    idempotency_key     TEXT,
    recorded_at         TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

-- Exactly one reservation and one settlement per invocation. Adjustments are
-- append-only and may repeat, so they are deliberately outside these indexes.
CREATE UNIQUE INDEX IF NOT EXISTS ux_budget_reservation
    ON task_budget_ledger(invocation_id) WHERE entry_kind = 'Reservation';
CREATE UNIQUE INDEX IF NOT EXISTS ux_budget_settlement
    ON task_budget_ledger(invocation_id) WHERE entry_kind = 'Settlement';

-- A repeated adjustment with the same idempotency key is the same decision.
CREATE UNIQUE INDEX IF NOT EXISTS ux_budget_adjustment_key
    ON task_budget_ledger(idempotency_key)
    WHERE entry_kind = 'Adjustment' AND idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_budget_task ON task_budget_ledger(task_id);
CREATE INDEX IF NOT EXISTS ix_budget_invocation ON task_budget_ledger(invocation_id);
"#;

/// M10 — Cancellation intent, execution identity and acknowledgements
/// (Phase 6.1D).
///
/// Three tables, because three different facts must survive a crash:
///
/// * `task_cancellation_intents` — someone *requested* cancellation. This is a
///   request, never evidence that execution stopped.
/// * `task_executions` — which cooperative execution loop is running. The
///   partial unique index allows at most one active execution per task, so an
///   old acknowledgement can never be mistaken for a newer loop's.
/// * `task_cancellation_acknowledgements` — that specific loop confirmed it
///   stopped, for that specific intent.
pub const M10_CANCELLATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_cancellation_intents (
    intent_id            TEXT PRIMARY KEY,
    task_id              TEXT NOT NULL UNIQUE,
    root_task_id         TEXT NOT NULL,
    requested_by_actor   TEXT NOT NULL,
    auth_method          TEXT NOT NULL,
    cancellation_reason  TEXT NOT NULL,
    requested_at         TEXT NOT NULL,
    deadline_at          TEXT NOT NULL,
    status               TEXT NOT NULL
                         CHECK (status IN ('Requested', 'Propagating',
                                           'AwaitingWorkers', 'Escalated', 'Completed')),
    escalated_at         TEXT,
    completed_at         TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE INDEX IF NOT EXISTS idx_cancellation_root
    ON task_cancellation_intents(root_task_id);

CREATE TABLE IF NOT EXISTS task_executions (
    execution_id TEXT PRIMARY KEY,
    task_id      TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('Active', 'Stopped')),
    stopped_at   TEXT,
    stop_reason  TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

-- At most one cooperative loop per task.
CREATE UNIQUE INDEX IF NOT EXISTS ux_task_active_execution
    ON task_executions(task_id) WHERE state = 'Active';

CREATE TABLE IF NOT EXISTS task_cancellation_acknowledgements (
    acknowledgement_id TEXT PRIMARY KEY,
    intent_id          TEXT NOT NULL,
    task_id            TEXT NOT NULL,
    execution_id       TEXT NOT NULL,
    last_step_number   INTEGER,
    final_status       TEXT NOT NULL,
    acknowledged_at    TEXT NOT NULL,
    UNIQUE (intent_id, execution_id),
    FOREIGN KEY (intent_id) REFERENCES task_cancellation_intents(intent_id),
    FOREIGN KEY (execution_id) REFERENCES task_executions(execution_id)
);
"#;

/// Apply the cancellation schema (Stage 6.1D.1).
pub fn apply_cancellation_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(M2_TASKS_SCHEMA)?;
    conn.execute_batch(M10_CANCELLATION_SCHEMA)?;
    Ok(())
}

/// Apply the delegation schema, its additive columns, and the budget ledger.
pub fn apply_delegation_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(M2_TASKS_SCHEMA)?;
    for (column, declaration) in M8_DELEGATION_COLUMNS {
        ensure_column(conn, "tasks", column, &format!("{column} {declaration}"))?;
    }
    conn.execute_batch(M8_DELEGATION_SCHEMA)?;
    conn.execute_batch(M9_BUDGET_SCHEMA)?;
    conn.execute_batch(M10_CANCELLATION_SCHEMA)?;
    Ok(())
}

pub const M3_ARTIFACTS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    task_id TEXT,
    artifact_type TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    location_uri TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_lineage (
    child_id TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    PRIMARY KEY (child_id, parent_id),
    FOREIGN KEY (child_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifacts_task_id ON artifacts(task_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_hash ON artifacts(hash);
CREATE INDEX IF NOT EXISTS idx_artifact_lineage_parent_id ON artifact_lineage(parent_id);
"#;

/// M4 — Durable execution ledger (Phase 5: Crash Recovery).
///
/// One row per in-progress or most-recently-completed agent step.
/// Written inside the same SQLite WAL transaction as task-state updates
/// so that checkpoint and state are always consistent.
///
/// Columns
/// ───────
/// task_id         : FK to tasks table
/// agent_id        : identifier of the agent that owns this execution
/// step_number     : monotonically increasing within a task execution
/// invocation_id   : UUID assigned to the active `ToolContext` (or NULL if not yet dispatched)
/// idempotency_key : caller-supplied deduplication token (or NULL)
/// semantics       : 'Idempotent' | 'AtMostOnce' | 'Reconcilable'
/// tool_id         : e.g. 'filesystem', 'git' (NULL before dispatch)
/// operation_id    : e.g. 'write_file', 'commit' (NULL before dispatch)
/// status          : 'Pending' | 'Dispatched' | 'RetryReady' | 'Succeeded' | 'Failed' | 'OutcomeUnknown'
/// checkpoint_time : RFC-3339 wall-clock time of last write
pub const M4_CHECKPOINT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_checkpoints (
    task_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    step_number     INTEGER NOT NULL,
    invocation_id   TEXT,
    idempotency_key TEXT,
    semantics       TEXT NOT NULL DEFAULT 'AtMostOnce',
    tool_id         TEXT,
    operation_id    TEXT,
    status          TEXT NOT NULL DEFAULT 'Pending',
    checkpoint_time TEXT NOT NULL,
    PRIMARY KEY (task_id, step_number)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON task_checkpoints(status);
CREATE INDEX IF NOT EXISTS idx_checkpoints_task_id ON task_checkpoints(task_id);
"#;

/// M5 — Recovery authorization (Phase 5.2: Fresh Grant Re-Authorization).
///
/// `task_authorization_context` is the durable record of *what* an invocation
/// was authorized to do.  It is written in the same transaction as the
/// `Pending` checkpoint so that a restart can never see a dispatchable
/// checkpoint without the capability intent that justified it.
///
/// `recovery_authorization_decisions` is the append-only audit trail of every
/// re-authorization attempt made by the recovery process.  A recovery pass that
/// cannot persist its decision must not resume the task.
///
/// Columns
/// ───────
/// capabilities       : JSON array of `Capability`
/// policy_id/version  : identity of the policy snapshot used at decision time
/// outcome            : 'Granted' | 'Denied'
pub const M5_RECOVERY_AUTHORIZATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_authorization_context (
    task_id        TEXT NOT NULL,
    step_number    INTEGER NOT NULL,
    agent_id       TEXT NOT NULL,
    capabilities   TEXT NOT NULL,
    policy_id      TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    recorded_at    TEXT NOT NULL,
    PRIMARY KEY (task_id, step_number)
);

CREATE TABLE IF NOT EXISTS recovery_authorization_decisions (
    decision_id            TEXT PRIMARY KEY,
    task_id                TEXT NOT NULL,
    step_number            INTEGER NOT NULL,
    agent_id               TEXT NOT NULL,
    outcome                TEXT NOT NULL,
    reason                 TEXT NOT NULL,
    grant_id               TEXT,
    requested_capabilities TEXT NOT NULL,
    policy_id              TEXT NOT NULL,
    policy_version         INTEGER NOT NULL,
    decided_at             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authz_decisions_task
    ON recovery_authorization_decisions(task_id, step_number);
"#;

/// M6 — Reconciliation and re-queue audit (Phase 5.4 operational contract).
///
/// Every action that moves an uncertain checkpoint or a blocked task forward is
/// recorded here with its actor, reason and evidence.  The checkpoint's own
/// identity is never rewritten by reconciliation; the prior status is preserved
/// in this row so the crash history stays legible afterwards.
pub const M6_RECONCILIATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS task_reconciliations (
    reconciliation_id TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    step_number       INTEGER NOT NULL,
    actor_id          TEXT NOT NULL,
    action            TEXT NOT NULL,
    reason            TEXT NOT NULL,
    evidence          TEXT NOT NULL,
    prior_status      TEXT NOT NULL,
    new_status        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    invocation_id     TEXT,
    verdict           TEXT,
    evidence_kind     TEXT,
    evidence_source   TEXT,
    evidence_json     TEXT,
    actor_kind        TEXT,
    auth_method       TEXT,
    grant_id          TEXT
);

CREATE INDEX IF NOT EXISTS idx_reconciliations_task
    ON task_reconciliations(task_id, step_number);
"#;

/// M7 — Phase 6.0 provenance columns.
///
/// Added after M6 shipped. `CREATE TABLE IF NOT EXISTS` cannot extend an
/// existing table, so these are applied with `ALTER TABLE` by
/// `apply_recovery_schema`. A row whose provenance columns are NULL predates
/// probe-driven reconciliation and must never be read as independently
/// verified.
pub const M7_RECONCILIATION_PROVENANCE_COLUMNS: [(&str, &str); 8] = [
    ("invocation_id", "TEXT"),
    ("verdict", "TEXT"),
    ("evidence_kind", "TEXT"),
    ("evidence_source", "TEXT"),
    ("evidence_json", "TEXT"),
    ("actor_kind", "TEXT"),
    ("auth_method", "TEXT"),
    ("grant_id", "TEXT"),
];

/// Additive column added after M5 shipped.
///
/// `required_capability` is the capability *family* the pending operation
/// requires, derived by the runtime from the tool manifest at dispatch time.
/// Recovery narrows the persisted intent to this family; it is never supplied
/// by the agent.
pub const M5_ADDENDUM_REQUIRED_CAPABILITY: &str = "required_capability TEXT";

/// Additive column added after M4 shipped.
///
/// `argument_fingerprint` is the canonical-argument SHA-256 that the
/// idempotency key was derived from.  Persisting it lets the runtime detect
/// "same key, different inputs" instead of silently reusing a previous result.
pub const M4_ADDENDUM_ARGUMENT_FINGERPRINT: &str = "argument_fingerprint TEXT";

/// Apply the checkpoint schema plus any additive columns on an existing
/// database.  `CREATE TABLE IF NOT EXISTS` cannot add columns to a table that
/// already exists, so addenda are applied with `ALTER TABLE`.
pub fn apply_checkpoint_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(M4_CHECKPOINT_SCHEMA)?;
    ensure_column(
        conn,
        "task_checkpoints",
        "argument_fingerprint",
        M4_ADDENDUM_ARGUMENT_FINGERPRINT,
    )?;
    Ok(())
}

/// Apply the full Phase 5 recovery schema: the checkpoint ledger, its additive
/// columns, and the Phase 5.2/5.4 authorization + reconciliation tables.
///
/// They are applied together because a checkpoint, its authorization context,
/// and its reconciliation record are written in one transaction — a database
/// that has one always has the others.
pub fn apply_recovery_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    apply_checkpoint_schema(conn)?;
    conn.execute_batch(M5_RECOVERY_AUTHORIZATION_SCHEMA)?;
    conn.execute_batch(M6_RECONCILIATION_SCHEMA)?;
    ensure_column(
        conn,
        "task_authorization_context",
        "required_capability",
        M5_ADDENDUM_REQUIRED_CAPABILITY,
    )?;
    for (column, declaration) in M7_RECONCILIATION_PROVENANCE_COLUMNS {
        ensure_column(
            conn,
            "task_reconciliations",
            column,
            &format!("{column} {declaration}"),
        )?;
    }
    Ok(())
}

/// Add `column` to `table` if it is not already present.
pub fn ensure_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> rusqlite::Result<()> {
    let already_present: bool = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        rusqlite::params![table, column],
        |row| row.get::<_, i64>(0),
    )? > 0;

    if !already_present {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {declaration}"))?;
    }
    Ok(())
}
