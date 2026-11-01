//! Phase 3B.3 — filesystem materialization and crash recovery.
//!
//! SQLite metadata publication is atomic; replacing a group of workspace
//! files is not. This module turns that gap into a durable, replayable state
//! machine:
//!
//! * Every committed transaction has journal rows written in the same
//!   database transaction as its manifest (see `transaction.rs`), so a
//!   recovery record always exists before any file is touched.
//! * Each file is applied by writing a temp file next to the target and
//!   atomically renaming it into place, then verified against its committed
//!   SHA-256 before the journal row is marked `materialized`.
//! * [`materialize_pending`] only ever processes `pending` rows, so a crash
//!   at any point — after commit but before the first file, halfway through
//!   a batch, or between a file write and its journal update — is recovered
//!   by calling it again: already-current files are recognized by content
//!   and not rewritten, revisions are never duplicated, and the batch is
//!   marked `materialized` only when every entry passes.
//!
//! **A journal makes materialization recoverable, not atomic.** Readers that
//! must never observe a mixed set of files need to read through the
//! manifest/snapshot interface; sequentially replacing ordinary workspace
//! files cannot offer group-wide visibility.

use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use chrono::Utc;
use rusqlite::Connection;

use crate::models::{
    ArtifactRevision, MaterializationRecord, MaterializationStatus, RevisionId, TransformError,
};
use crate::store::ArtifactRevisionStore;

/// One journal row still awaiting file application, in publication order.
pub(crate) struct PendingEntry {
    pub transaction_id: String,
    pub ordinal: i64,
    pub artifact_id: String,
    pub revision_id: RevisionId,
}

/// Result of one `materialize_pending` run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MaterializationSummary {
    /// Files written or replaced during this run.
    pub applied: usize,
    /// Files already holding their committed bytes (crash replay / retries).
    pub already_current: usize,
    /// Transactions that reached `Materialized` during this run.
    pub completed_transactions: Vec<String>,
}

/// Normalize a workspace-relative path to its canonical key form:
/// `/`-separated, no `.`/`..` components, no absolute root, non-empty.
///
/// The returned string *is* the artifact identity used for head lookups,
/// duplicate detection, containment checks and authorization — one canonical
/// spelling across reads, writes and expectations.
pub(crate) fn normalize_relative(relative: &str) -> Result<String, TransformError> {
    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TransformError::UnsafePath {
                    path: relative.to_owned(),
                    reason: "parent traversal (`..`) is not allowed".to_owned(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(TransformError::UnsafePath {
                    path: relative.to_owned(),
                    reason: "absolute paths are not allowed".to_owned(),
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(TransformError::InvalidProposal(
            "path must not be empty".to_owned(),
        ));
    }
    Ok(parts.join("/"))
}

/// Resolve a canonical relative path to a real target path, rejecting
/// anything that could escape the workspace.
///
/// Symlink-safe: the deepest existing ancestor (including the target itself)
/// is fully canonicalized and must remain inside the canonicalized workspace
/// root, so a symlink pointing outside — whether the link itself or a parent
/// directory is the escape — is rejected *before* publication or writing.
pub(crate) fn resolve_target(
    workspace_root: &Path,
    relative: &str,
) -> Result<PathBuf, TransformError> {
    let normalized = normalize_relative(relative)?;
    let root = std::fs::canonicalize(workspace_root).map_err(|e| TransformError::UnsafePath {
        path: relative.to_owned(),
        reason: format!("workspace root cannot be canonicalized: {e}"),
    })?;

    // Walk up to the deepest ancestor that exists (symlink_metadata does not
    // follow the final link, so a link at the target itself is detected too).
    let full = root.join(&normalized);
    let mut candidate = full.as_path();
    let existing = loop {
        if std::fs::symlink_metadata(candidate).is_ok() {
            break candidate;
        }
        match candidate.parent() {
            Some(parent) if parent.starts_with(&root) => candidate = parent,
            _ => break root.as_path(),
        }
    };
    let resolved = std::fs::canonicalize(existing).map_err(|e| TransformError::UnsafePath {
        path: relative.to_owned(),
        reason: format!("path ancestor cannot be canonicalized: {e}"),
    })?;
    if !resolved.starts_with(&root) {
        return Err(TransformError::UnsafePath {
            path: relative.to_owned(),
            reason: "path resolves outside the workspace (symlink escape)".to_owned(),
        });
    }
    Ok(full)
}

/// Load every pending journal entry across all committed batches, in
/// publication order (transactions by commit time, then ordinal).
pub(crate) fn load_pending(conn: &Connection) -> Result<Vec<PendingEntry>, TransformError> {
    let mut statement = conn.prepare(
        "SELECT j.transaction_id, j.ordinal, j.artifact_id, j.revision_id
         FROM materialization_journal j
         JOIN transform_transactions t ON t.transaction_id = j.transaction_id
         WHERE j.status = 'pending'
         ORDER BY t.committed_at ASC, t.rowid ASC, j.ordinal ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut entries = Vec::new();
    for row in rows {
        let (transaction_id, ordinal, artifact_id, revision_id) = row?;
        entries.push(PendingEntry {
            transaction_id,
            ordinal,
            artifact_id,
            revision_id: RevisionId::from_str(&revision_id)?,
        });
    }
    Ok(entries)
}

/// All journal rows of one transaction (recovery / inspection view).
pub(crate) fn journal_records(
    conn: &Connection,
    transaction_id: &str,
) -> Result<Vec<MaterializationRecord>, TransformError> {
    let mut statement = conn.prepare(
        "SELECT ordinal, artifact_id, revision_id, status, updated_at
         FROM materialization_journal WHERE transaction_id = ?1
         ORDER BY ordinal ASC",
    )?;
    let rows = statement.query_map([transaction_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (ordinal, artifact_id, revision_id, status, updated_at) = row?;
        records.push(MaterializationRecord {
            transaction_id: transaction_id.to_owned(),
            ordinal,
            artifact_id,
            revision_id: RevisionId::from_str(&revision_id)?,
            status: MaterializationStatus::from_db(&status)?,
            updated_at: parse_timestamp(&updated_at)?,
        });
    }
    Ok(records)
}

/// Mark one journal entry materialized and, when that was the last pending
/// entry of its batch, flip the transaction to `materialized` — both writes
/// inside one SQLite transaction, so a crash can never separate them.
///
/// Returns `true` when the batch is fully materialized as of this call.
/// Losing a completion write is safe either way: the entry stays `pending`,
/// the next run finds the file already holding its bytes, marks it again
/// without rewriting, and completes the batch.
pub(crate) fn mark_materialized(
    conn: &mut Connection,
    transaction_id: &str,
    ordinal: i64,
) -> Result<bool, TransformError> {
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE materialization_journal SET status = 'materialized', updated_at = ?1
         WHERE transaction_id = ?2 AND ordinal = ?3",
        rusqlite::params![now, transaction_id, ordinal],
    )?;
    tx.execute(
        "UPDATE transform_transactions
         SET state = 'materialized', materialized_at = ?1
         WHERE transaction_id = ?2 AND state = 'committed'
           AND NOT EXISTS (
               SELECT 1 FROM materialization_journal
               WHERE transaction_id = ?2 AND status <> 'materialized'
           )",
        rusqlite::params![now, transaction_id],
    )?;
    tx.commit()?;

    let still_pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM materialization_journal
         WHERE transaction_id = ?1 AND status <> 'materialized'",
        [transaction_id],
        |row| row.get(0),
    )?;
    Ok(still_pending == 0)
}

/// Heal any batch whose journal is fully materialized while its manifest is
/// still `committed` (a completion write lost between the two updates on an
/// older/partial state). Returns the healed transaction ids.
pub(crate) fn reconcile_completed(conn: &Connection) -> Result<Vec<String>, TransformError> {
    let mut statement = conn.prepare(
        "SELECT transaction_id FROM transform_transactions
         WHERE state = 'committed'
           AND NOT EXISTS (
               SELECT 1 FROM materialization_journal j
               WHERE j.transaction_id = transform_transactions.transaction_id
                 AND j.status <> 'materialized'
           )",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut healed = Vec::new();
    for row in rows {
        healed.push(row?);
    }
    let now = Utc::now().to_rfc3339();
    for transaction_id in &healed {
        conn.execute(
            "UPDATE transform_transactions
             SET state = 'materialized', materialized_at = ?1
             WHERE transaction_id = ?2",
            rusqlite::params![now, transaction_id],
        )?;
    }
    Ok(healed)
}

/// Apply every pending journal entry in publication order.
///
/// This is both the normal materialization path and crash recovery: calling
/// it on a freshly opened store resumes any interrupted batch from committed
/// revision bytes. On a per-file conflict it returns
/// [`TransformError::MaterializationConflict`] *after* persisting the
/// progress of earlier files — the batch stays `committed` with its
/// `pending` rows intact so the conflict can be reconciled and this called
/// again. A conflict never mutates revision metadata or heads.
pub(crate) fn materialize_pending(
    store: &mut ArtifactRevisionStore,
    workspace_root: &Path,
) -> Result<MaterializationSummary, TransformError> {
    let entries = load_pending(store.connection())?;
    let mut summary = MaterializationSummary::default();
    // Heal any batch whose journal completed but whose manifest state update
    // was lost, before deciding what is left to do.
    summary
        .completed_transactions
        .extend(reconcile_completed(store.connection())?);

    for entry in &entries {
        let revision = store.get_revision(entry.revision_id.as_str())?;
        let parent = match &revision.parent_id {
            Some(parent_id) => Some(store.get_revision(parent_id.as_str())?),
            None => None,
        };
        // Re-verifying read: bytes are hash-checked against the revision.
        let bytes = store.read_content(revision.id.as_str())?;
        let target = resolve_target(workspace_root, &entry.artifact_id)?;

        match apply(&entry.artifact_id, &target, parent.as_ref(), &bytes, store)? {
            ApplyOutcome::Applied => summary.applied += 1,
            ApplyOutcome::AlreadyCurrent => summary.already_current += 1,
        }

        let completed =
            mark_materialized(store.connection(), &entry.transaction_id, entry.ordinal)?;
        if completed {
            summary
                .completed_transactions
                .push(entry.transaction_id.clone());
        }
    }

    Ok(summary)
}

#[derive(Debug, PartialEq, Eq)]
enum ApplyOutcome {
    /// Bytes were written (created or replaced) and verified.
    Applied,
    /// The target already holds exactly the committed bytes; nothing written.
    AlreadyCurrent,
}

/// Apply one file according to the conflict policy:
///
/// * target holds the committed bytes → done (idempotent replay),
/// * target holds the expected parent revision's bytes → atomically replace,
/// * target holds anything else (external edit, untracked content, a
///   directory, or is missing while a parent exists) → `MaterializationConflict`;
///   the file is **not** touched.
fn apply(
    artifact_id: &str,
    target: &Path,
    parent: Option<&ArtifactRevision>,
    new_bytes: &[u8],
    store: &ArtifactRevisionStore,
) -> Result<ApplyOutcome, TransformError> {
    if target.exists() {
        if !target.is_file() {
            return Err(TransformError::MaterializationConflict {
                path: artifact_id.to_owned(),
                reason: "target exists but is not a regular file".to_owned(),
            });
        }
        let on_disk = std::fs::read(target)?;
        if on_disk == new_bytes {
            return Ok(ApplyOutcome::AlreadyCurrent);
        }
        match parent {
            None => {
                return Err(TransformError::MaterializationConflict {
                    path: artifact_id.to_owned(),
                    reason: "target exists with untracked content; refusing to overwrite it"
                        .to_owned(),
                });
            }
            Some(parent) => {
                let expected = store.read_content(parent.id.as_str())?;
                if on_disk != expected {
                    return Err(TransformError::MaterializationConflict {
                        path: artifact_id.to_owned(),
                        reason: format!(
                            "target changed externally: it holds bytes matching neither the \
                             committed content nor the expected previous revision {}",
                            parent.id
                        ),
                    });
                }
            }
        }
    } else if parent.is_some() {
        return Err(TransformError::MaterializationConflict {
            path: artifact_id.to_owned(),
            reason: "expected the previous revision on disk, but the target is missing \
                     (externally deleted)"
                .to_owned(),
        });
    }

    write_atomic(target, new_bytes)?;
    Ok(ApplyOutcome::Applied)
}

/// Temp-file + atomic per-file replacement. The target only ever holds the
/// old bytes or the complete new bytes, never a truncated mix.
fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), TransformError> {
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_owned());
    let temp = target.with_file_name(format!(".{file_name}.tmp-{}", uuid::Uuid::new_v4()));
    let result = std::fs::write(&temp, bytes).and_then(|_| std::fs::rename(&temp, target));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    Ok(())
}

fn parse_timestamp(raw: &str) -> Result<chrono::DateTime<Utc>, TransformError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| TransformError::InvalidTimestamp(raw.to_owned()))
}
