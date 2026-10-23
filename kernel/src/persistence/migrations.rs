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
/// status          : 'Pending' | 'Dispatched' | 'Succeeded' | 'Failed' | 'OutcomeUnknown'
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

