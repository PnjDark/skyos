use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};

use kernel::artifacts::registry::{ArtifactRegistry, ArtifactType};

use crate::models::{
    ArtifactRevision, ProposedChange, RevisionExpectation, RevisionId, TransformError,
};

const REVISIONS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS artifact_revisions (
    revision_id         TEXT PRIMARY KEY,
    artifact_id         TEXT NOT NULL,
    parent_revision_id  TEXT REFERENCES artifact_revisions(revision_id),
    content_hash        TEXT NOT NULL,
    task_id             TEXT NOT NULL,
    committed_by_agent  TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    committed_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifact_revisions_artifact
    ON artifact_revisions(artifact_id, committed_at);
CREATE TABLE IF NOT EXISTS revision_heads (
    artifact_id  TEXT PRIMARY KEY,
    revision_id  TEXT NOT NULL REFERENCES artifact_revisions(revision_id),
    updated_at   TEXT NOT NULL
);
";

/// Phase 3B.3: transaction manifests and the durable materialization
/// journal. Journal rows are inserted in the *same* SQLite transaction as
/// the manifest, revisions and head promotions, so every committed batch has
/// a recovery record from the instant it becomes visible — and a rolled-back
/// batch leaves no rows at all.
const TRANSACTION_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS transform_transactions (
    transaction_id  TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    -- SHA-256 of the canonical proposal; the idempotency key's twin.
    proposal_hash   TEXT NOT NULL,
    state           TEXT NOT NULL,
    committed_at    TEXT NOT NULL,
    materialized_at TEXT
);
CREATE TABLE IF NOT EXISTS materialization_journal (
    transaction_id TEXT NOT NULL REFERENCES transform_transactions(transaction_id),
    ordinal        INTEGER NOT NULL,
    artifact_id    TEXT NOT NULL,
    revision_id    TEXT NOT NULL REFERENCES artifact_revisions(revision_id),
    status         TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (transaction_id, ordinal)
);
";

/// Text used for the absent side of a `MergeConflict` (no expected or actual
/// revision), so callers can distinguish "no head" from a real revision id.
const NONE_REVISION: &str = "<none>";

/// Immutable artifact revision store (Phase 3B.1).
///
/// Content bytes live in the kernel `ArtifactRegistry` CAS
/// (`store_root/sha256/<hash>`); revision rows and head pointers live in
/// transform-owned tables in the same runtime database. Blobs written by a
/// failed or abandoned flow may remain unreferenced — that is safe and can
/// be garbage-collected later. Revision metadata and heads are only ever
/// published inside a single SQLite transaction, so readers see either the
/// old head or the new head, never a partial state.
pub struct ArtifactRevisionStore {
    registry: ArtifactRegistry,
    metadata: Connection,
    store_root: PathBuf,
}

impl ArtifactRevisionStore {
    /// Open (creating if needed) the revision store over `db_path`, storing
    /// CAS blobs under `store_root`.
    pub fn open(
        db_path: impl AsRef<Path>,
        store_root: impl AsRef<Path>,
    ) -> Result<Self, TransformError> {
        let registry = ArtifactRegistry::open(&db_path, &store_root)?;
        let metadata = Connection::open(&db_path)?;
        metadata.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
        )?;
        metadata.execute_batch(REVISIONS_SCHEMA)?;
        metadata.execute_batch(TRANSACTION_SCHEMA)?;

        Ok(Self {
            registry,
            metadata,
            store_root: store_root.as_ref().to_path_buf(),
        })
    }

    /// Compute the canonical SHA-256 (lowercase hex) of `content`.
    pub fn checksum_of(content: &[u8]) -> String {
        hex::encode(Sha256::digest(content))
    }

    /// Absolute path of the CAS blob for `checksum`.
    pub fn blob_path(&self, checksum: &str) -> PathBuf {
        self.store_root.join("sha256").join(checksum)
    }

    /// Borrow the metadata connection (write side; used to open the
    /// publication transactions that own batch commits).
    pub(crate) fn connection(&mut self) -> &mut Connection {
        &mut self.metadata
    }

    /// Borrow the metadata connection read-only (manifest/journal queries).
    pub(crate) fn ro_connection(&self) -> &Connection {
        &self.metadata
    }

    /// Stage `content` in the kernel CAS registry and return its canonical
    /// SHA-256. The registry owns a separate connection, so this write can
    /// never join the metadata transaction that publishes revisions — it
    /// happens beforehand, and a blob orphaned by a later rollback is safe
    /// (immutable, deduplicated, collectable).
    pub(crate) fn stage_blob(
        &mut self,
        artifact_id: &str,
        content: &[u8],
        task_id: &str,
    ) -> Result<String, TransformError> {
        let checksum = Self::checksum_of(content);
        let staging = self
            .store_root
            .join(format!("tmp_rev_{}", uuid::Uuid::new_v4()));
        std::fs::write(&staging, content)?;
        let register_result = self.registry.register_file_artifact(
            &staging,
            Some(task_id),
            ArtifactType::File,
            None,
            json!({ "module": "skyos-transform", "artifact": artifact_id }),
        );
        let _ = std::fs::remove_file(&staging);
        register_result?;
        Ok(checksum)
    }

    /// Append a new revision for `artifact_id` containing `content` and
    /// publish it as the artifact's head atomically.
    ///
    /// The parent of the new revision is whatever head is visible at commit
    /// time. Enforcing caller *expectations* about that head is the OCC
    /// stage (3B.2); this call guarantees structural integrity only:
    /// metadata for a revision and its head promotion become visible
    /// together or not at all.
    pub fn append(
        &mut self,
        artifact_id: &str,
        content: &[u8],
        task_id: &str,
        agent_id: &str,
    ) -> Result<ArtifactRevision, TransformError> {
        // 1. Persist content through the kernel CAS registry. Deduplicated
        //    by hash; an orphan blob from a later metadata failure is safe.
        let checksum = self.stage_blob(artifact_id, content, task_id)?;

        // 2. Publish revision metadata + head in one transaction.
        // IMMEDIATE: take the write lock up front so concurrent appends wait
        // on busy_timeout instead of failing on a read→write upgrade, and
        // read the parent head under that lock (no stale-parent window).
        let tx = self
            .metadata
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let parent_id: Option<String> = tx
            .query_row(
                "SELECT revision_id FROM revision_heads WHERE artifact_id = ?1",
                [artifact_id],
                |row| row.get(0),
            )
            .optional()?;
        let parent_id = parent_id.map(|id| RevisionId::from_str(&id)).transpose()?;
        let committed_at = Utc::now();
        let revision = ArtifactRevision {
            id: RevisionId::new(),
            artifact_id: artifact_id.to_owned(),
            parent_id,
            checksum,
            task_id: task_id.to_owned(),
            committed_by_agent: agent_id.to_owned(),
            size_bytes: content.len() as u64,
            committed_at,
        };
        Self::publish_in_tx(&tx, &revision)?;
        tx.commit()?;

        Ok(revision)
    }

    /// Append a new revision for `change.path` **only if** the caller's
    /// expectation still holds, publishing it as the artifact's head — as one
    /// atomic operation (Phase 3B.2).
    ///
    /// The expectation is evaluated against the head read *inside* the same
    /// `IMMEDIATE` transaction that inserts the revision and promotes the head.
    /// The write lock serializes concurrent committers, so of two proposals
    /// based on the same head exactly one can promote; the loser observes the
    /// moved head and returns `MergeConflict` carrying the winner's revision,
    /// with no revision row inserted and no head pointer moved. (The CAS blob
    /// may already have been written at that point; an unreferenced immutable
    /// blob is safe and collectable later.)
    ///
    /// Storage failures surface as `Database`/`Registry` errors, never as
    /// `MergeConflict` — only expectation failures are conflicts.
    pub fn append_if_head_matches(
        &mut self,
        change: &ProposedChange,
        task_id: &str,
        agent_id: &str,
    ) -> Result<ArtifactRevision, TransformError> {
        // Structured expectation errors are caller bugs; reject them before
        // writing anything to the CAS.
        Self::validate_expectation_shape(&change.path, &change.expectation)?;

        // 1. Persist content through the kernel CAS registry. The registry owns
        //    a separate connection, so this write cannot join the metadata
        //    transaction below and must happen first.
        let checksum = self.stage_blob(&change.path, &change.content, task_id)?;

        // 2. Validate the expectation and promote the head atomically.
        //    IMMEDIATE acquires the write lock up front, so the head read below
        //    cannot race another committer: either this transaction sees the
        //    head the caller expected and publishes, or it observes the moved
        //    head and returns a conflict. Dropping `tx` without committing
        //    (the `?` paths above and below) rolls everything back.
        let tx = self
            .metadata
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let head = Self::head_in_tx(&tx, &change.path)?;
        Self::evaluate_expectation(&change.path, &change.expectation, head.as_ref())?;

        let revision = ArtifactRevision {
            id: RevisionId::new(),
            artifact_id: change.path.clone(),
            parent_id: head.as_ref().map(|h| h.id.clone()),
            checksum,
            task_id: task_id.to_owned(),
            committed_by_agent: agent_id.to_owned(),
            size_bytes: change.content.len() as u64,
            committed_at: Utc::now(),
        };
        Self::publish_in_tx(&tx, &revision)?;
        tx.commit()?;

        Ok(revision)
    }

    /// Pure evaluation of a caller's expectation against a known head; never
    /// mutates state.
    ///
    /// `append_if_head_matches` performs this exact check inside its write
    /// transaction — that in-transaction call is the only concurrency-safe
    /// enforcement point. Calling this against a separately-read head is a
    /// preflight aid only and must never be treated as the commit protocol.
    pub fn evaluate_expectation(
        path: &str,
        expectation: &RevisionExpectation,
        head: Option<&ArtifactRevision>,
    ) -> Result<(), TransformError> {
        Self::validate_expectation_shape(path, expectation)?;

        match (&expectation.expected_revision, head) {
            (None, None) => Ok(()),
            (None, Some(actual)) => Err(TransformError::MergeConflict {
                path: path.to_owned(),
                expected_revision: NONE_REVISION.to_owned(),
                actual_revision: actual.id.to_string(),
                reason: "first write expected no existing head".to_owned(),
            }),
            (Some(expected_id), None) => Err(TransformError::MergeConflict {
                path: path.to_owned(),
                expected_revision: expected_id.to_string(),
                actual_revision: NONE_REVISION.to_owned(),
                reason: "expected revision is not the current head: no head exists".to_owned(),
            }),
            (Some(expected_id), Some(actual)) => {
                if &actual.id != expected_id {
                    return Err(TransformError::MergeConflict {
                        path: path.to_owned(),
                        expected_revision: expected_id.to_string(),
                        actual_revision: actual.id.to_string(),
                        reason: "stale revision: the artifact head has moved".to_owned(),
                    });
                }
                if let Some(expected_checksum) = &expectation.expected_checksum {
                    if expected_checksum != &actual.checksum {
                        return Err(TransformError::MergeConflict {
                            path: path.to_owned(),
                            expected_revision: expected_id.to_string(),
                            actual_revision: actual.id.to_string(),
                            reason: format!(
                                "checksum mismatch on the expected head: expected {expected_checksum}, head has {}",
                                actual.checksum
                            ),
                        });
                    }
                }
                Ok(())
            }
        }
    }

    /// Reject expectations that are structurally inconsistent before any
    /// storage work: the expectation must name the same artifact as the change
    /// (the canonical path *is* the artifact identity in this store), and a
    /// checksum pin requires an expected revision to pin it against.
    pub(crate) fn validate_expectation_shape(
        path: &str,
        expectation: &RevisionExpectation,
    ) -> Result<(), TransformError> {
        if expectation.artifact_id != path {
            return Err(TransformError::InconsistentExpectation {
                path: path.to_owned(),
                reason: format!(
                    "expectation names artifact '{}' but the change targets '{path}'",
                    expectation.artifact_id
                ),
            });
        }
        if expectation.expected_revision.is_none() && expectation.expected_checksum.is_some() {
            return Err(TransformError::InconsistentExpectation {
                path: path.to_owned(),
                reason: "checksum pinned without an expected revision".to_owned(),
            });
        }
        Ok(())
    }

    /// Current head as seen inside `tx`, if any.
    pub(crate) fn head_in_tx(
        tx: &rusqlite::Transaction<'_>,
        artifact_id: &str,
    ) -> Result<Option<ArtifactRevision>, TransformError> {
        let head = tx
            .query_row(
                "SELECT r.revision_id, r.artifact_id, r.parent_revision_id, r.content_hash,
                        r.task_id, r.committed_by_agent, r.size_bytes, r.committed_at
                 FROM revision_heads h
                 JOIN artifact_revisions r ON r.revision_id = h.revision_id
                 WHERE h.artifact_id = ?1",
                [artifact_id],
                row_to_revision,
            )
            .optional()?;
        Ok(head)
    }

    /// Insert a revision row and promote its head pointer inside `tx`; the
    /// caller commits both or neither as one unit.
    pub(crate) fn publish_in_tx(
        tx: &rusqlite::Transaction<'_>,
        revision: &ArtifactRevision,
    ) -> Result<(), TransformError> {
        tx.execute(
            "INSERT INTO artifact_revisions
             (revision_id, artifact_id, parent_revision_id, content_hash,
              task_id, committed_by_agent, size_bytes, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                revision.id.as_str(),
                revision.artifact_id,
                revision.parent_id.as_ref().map(|p| p.as_str()),
                revision.checksum,
                revision.task_id,
                revision.committed_by_agent,
                revision.size_bytes,
                revision.committed_at.to_rfc3339(),
            ],
        )?;
        tx.execute(
            "INSERT INTO revision_heads (artifact_id, revision_id, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(artifact_id) DO UPDATE SET
                 revision_id = excluded.revision_id,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                revision.artifact_id,
                revision.id.as_str(),
                revision.committed_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Current head revision of `artifact_id`, if any.
    pub fn head(&self, artifact_id: &str) -> Result<Option<ArtifactRevision>, TransformError> {
        let revision_id: Option<String> = self
            .metadata
            .query_row(
                "SELECT revision_id FROM revision_heads WHERE artifact_id = ?1",
                [artifact_id],
                |row| row.get(0),
            )
            .optional()?;
        match revision_id {
            Some(id) => self.get_revision(&id).map(Some),
            None => Ok(None),
        }
    }

    /// Current head revision id of `artifact_id` (OCC fast path).
    pub fn head_revision_id(
        &self,
        artifact_id: &str,
    ) -> Result<Option<RevisionId>, TransformError> {
        self.metadata
            .query_row(
                "SELECT revision_id FROM revision_heads WHERE artifact_id = ?1",
                [artifact_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|id| RevisionId::from_str(&id))
            .transpose()
    }

    /// Look up a revision by id.
    pub fn get_revision(&self, revision_id: &str) -> Result<ArtifactRevision, TransformError> {
        self.metadata
            .query_row(
                "SELECT revision_id, artifact_id, parent_revision_id, content_hash,
                        task_id, committed_by_agent, size_bytes, committed_at
                 FROM artifact_revisions WHERE revision_id = ?1",
                [revision_id],
                row_to_revision,
            )
            .optional()?
            .ok_or_else(|| TransformError::RevisionNotFound(revision_id.to_owned()))
    }

    /// Full revision history of an artifact, oldest first.
    pub fn revisions_for(
        &self,
        artifact_id: &str,
    ) -> Result<Vec<ArtifactRevision>, TransformError> {
        let mut statement = self.metadata.prepare(
            "SELECT revision_id, artifact_id, parent_revision_id, content_hash,
                    task_id, committed_by_agent, size_bytes, committed_at
             FROM artifact_revisions WHERE artifact_id = ?1
             ORDER BY committed_at ASC, rowid ASC",
        )?;
        let rows = statement.query_map([artifact_id], row_to_revision)?;
        rows.map(|row| row.map_err(TransformError::from)).collect()
    }

    /// Read the content of a revision, verifying the stored bytes still
    /// reproduce their recorded SHA-256.
    pub fn read_content(&self, revision_id: &str) -> Result<Vec<u8>, TransformError> {
        let revision = self.get_revision(revision_id)?;
        let blob = self.blob_path(&revision.checksum);
        if !blob.exists() {
            return Err(TransformError::BlobMissing(revision.checksum.clone()));
        }
        let bytes = std::fs::read(&blob)?;
        let actual = Self::checksum_of(&bytes);
        if actual != revision.checksum {
            return Err(TransformError::ChecksumMismatch {
                revision_id: revision.id.to_string(),
                expected: revision.checksum,
                calculated: actual,
            });
        }
        Ok(bytes)
    }
}

fn row_to_revision(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactRevision> {
    let id: String = row.get(0)?;
    let parent: Option<String> = row.get(2)?;
    let committed_at: String = row.get(7)?;
    let committed_at = DateTime::parse_from_rfc3339(&committed_at)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?
        .with_timezone(&Utc);

    Ok(ArtifactRevision {
        id: RevisionId::from_str(&id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )),
            )
        })?,
        artifact_id: row.get(1)?,
        parent_id: parent
            .map(|p| {
                RevisionId::from_str(&p).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )),
                    )
                })
            })
            .transpose()?,
        checksum: row.get(3)?,
        task_id: row.get(4)?,
        committed_by_agent: row.get(5)?,
        size_bytes: row.get(6)?,
        committed_at,
    })
}
