//! Phase 3B.3 — atomic multi-file transaction publication.
//!
//! Publication separates two atomicity domains that must never be conflated:
//!
//! * **Metadata** — a batch's manifest, its revisions, its head promotions
//!   and its materialization-journal rows are written inside **one** SQLite
//!   `IMMEDIATE` transaction. Every expectation is revalidated against heads
//!   read under the write lock, so overlapping batches have exactly one
//!   winner and a batch with any stale expectation publishes nothing at all:
//!   no manifest, no revisions, no head movement, no journal rows. The
//!   journal is committed *with* the manifest, so every committed batch has
//!   a durable recovery record from the instant it becomes visible.
//! * **Filesystem** — workspace files cannot be replaced as a group
//!   atomically. [`TransactionEngine::materialize_pending`] applies
//!   committed bytes per file (temp file + atomic rename) with per-file
//!   journal progress, so materialization is *recoverable by replay*, not
//!   atomic. Readers that must never observe a mixed set of files should
//!   read through the manifest/snapshot interface rather than raw paths.
//!
//! `transaction_id` is the idempotency key: replaying a committed id with an
//! identical proposal returns the existing manifest without publishing
//! anything new; reusing the id with different content is rejected with
//! [`TransformError::TransactionIdConflict`].

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use crate::materializer::{self, MaterializationSummary};
use crate::models::{
    ArtifactRevision, CommittedChange, MaterializationRecord, MaterializationStatus,
    MultiFileProposal, RevisionExpectation, RevisionId, TransactionManifest, TransactionState,
    TransformError,
};
use crate::store::ArtifactRevisionStore;

/// One change validated for publication: canonical path, pinned expectation,
/// content hash and size of the bytes already staged in the CAS.
struct PreparedChange {
    path: String,
    expectation: RevisionExpectation,
    checksum: String,
    size_bytes: u64,
}

/// Batch publication façade over an [`ArtifactRevisionStore`].
///
/// Owns the workspace root so every path — at publication *and* at materialization
/// time — is revalidated for canonical form and containment.
pub struct TransactionEngine<'a> {
    store: &'a mut ArtifactRevisionStore,
    workspace_root: PathBuf,
}

impl<'a> TransactionEngine<'a> {
    pub fn new(store: &'a mut ArtifactRevisionStore, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            store,
            workspace_root: workspace_root.into(),
        }
    }

    /// Publish `proposal` atomically.
    ///
    /// Phase 1 (*prepare*, outside the publication transaction): validate
    /// structure — non-empty id, non-empty change set, canonical contained
    /// paths, no duplicate targets, well-formed expectations — then stage
    /// content-addressed blobs. Blobs orphaned by a later conflict are safe:
    /// immutable, deduplicated, collectable.
    ///
    /// Phase 2 (*publish*, one `IMMEDIATE` transaction): check
    /// `transaction_id` reuse, revalidate every expected head under the
    /// write lock, then insert the manifest, all revisions, all head
    /// promotions and all durable journal entries together. Any conflict
    /// aborts the whole transaction — no partial metadata, ever.
    ///
    /// Phase 3 (materialization) is deliberately *not* performed here; call
    /// [`Self::materialize_pending`] (also the crash-recovery entry point).
    pub fn commit(
        &mut self,
        proposal: &MultiFileProposal,
    ) -> Result<TransactionManifest, TransformError> {
        // ---- Phase 1: prepare ----
        if proposal.transaction_id.trim().is_empty() {
            return Err(TransformError::InvalidProposal(
                "transaction_id must not be empty".to_owned(),
            ));
        }
        if proposal.changes.is_empty() {
            return Err(TransformError::InvalidProposal(
                "proposal contains no changes".to_owned(),
            ));
        }

        let mut seen_paths = HashSet::with_capacity(proposal.changes.len());
        let mut prepared = Vec::with_capacity(proposal.changes.len());
        for change in &proposal.changes {
            let canonical = materializer::normalize_relative(&change.path)?;
            if canonical != change.path {
                return Err(TransformError::UnsafePath {
                    path: change.path.clone(),
                    reason: "path is not in canonical relative form \
                             (forward-slash separated, no `.` or `..` components)"
                        .to_owned(),
                });
            }
            if !seen_paths.insert(canonical.clone()) {
                return Err(TransformError::DuplicatePath(canonical));
            }
            // Containment + symlink-escape check against the real workspace.
            materializer::resolve_target(&self.workspace_root, &change.path)?;
            ArtifactRevisionStore::validate_expectation_shape(&change.path, &change.expectation)?;

            let checksum =
                self.store
                    .stage_blob(&change.path, &change.content, &proposal.task_id)?;
            prepared.push(PreparedChange {
                path: change.path.clone(),
                expectation: change.expectation.clone(),
                checksum,
                size_bytes: change.content.len() as u64,
            });
        }
        let proposal_hash = Self::proposal_hash(proposal, &prepared);

        // ---- Phase 2: publish ----
        // IMMEDIATE takes the write lock up front, so the idempotency check
        // and every head read below are race-free: two batches overlapping on
        // any artifact serialize, the loser observes the moved head and the
        // `?` paths roll the whole transaction back.
        let tx = self
            .store
            .connection()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Transaction-id idempotency, checked inside the publication lock.
        let existing_hash: Option<String> = tx
            .query_row(
                "SELECT proposal_hash FROM transform_transactions WHERE transaction_id = ?1",
                [proposal.transaction_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_hash) = existing_hash {
            if existing_hash != proposal_hash {
                return Err(TransformError::TransactionIdConflict {
                    transaction_id: proposal.transaction_id.clone(),
                    reason: "reused with a different proposal".to_owned(),
                });
            }
            // Identical replay: return the existing manifest, publish nothing.
            let manifest = Self::manifest_conn(&tx, &proposal.transaction_id)?;
            tx.commit()?;
            return Ok(manifest);
        }

        let now = Utc::now();
        let mut revisions = Vec::with_capacity(prepared.len());
        for change in &prepared {
            let head = ArtifactRevisionStore::head_in_tx(&tx, &change.path)?;
            ArtifactRevisionStore::evaluate_expectation(
                &change.path,
                &change.expectation,
                head.as_ref(),
            )?;
            revisions.push(ArtifactRevision {
                id: RevisionId::new(),
                artifact_id: change.path.clone(),
                parent_id: head.as_ref().map(|h| h.id.clone()),
                checksum: change.checksum.clone(),
                task_id: proposal.task_id.clone(),
                committed_by_agent: proposal.agent_id.clone(),
                size_bytes: change.size_bytes,
                committed_at: now,
            });
        }

        tx.execute(
            "INSERT INTO transform_transactions
             (transaction_id, task_id, agent_id, proposal_hash, state, committed_at, materialized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            rusqlite::params![
                proposal.transaction_id,
                proposal.task_id,
                proposal.agent_id,
                proposal_hash,
                TransactionState::Committed.as_str(),
                now.to_rfc3339(),
            ],
        )?;
        for (ordinal, (change, revision)) in prepared.iter().zip(revisions.iter()).enumerate() {
            // Revision row + head promotion + journal record, all inside the
            // one publication transaction.
            ArtifactRevisionStore::publish_in_tx(&tx, revision)?;
            tx.execute(
                "INSERT INTO materialization_journal
                 (transaction_id, ordinal, artifact_id, revision_id, status, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    proposal.transaction_id,
                    ordinal as i64,
                    change.path,
                    revision.id.as_str(),
                    MaterializationStatus::Pending.as_str(),
                    now.to_rfc3339(),
                ],
            )?;
        }
        tx.commit()?;

        Self::manifest_conn(self.store.ro_connection(), &proposal.transaction_id)
    }

    /// Look up a committed batch's manifest.
    pub fn manifest(&self, transaction_id: &str) -> Result<TransactionManifest, TransformError> {
        Self::manifest_conn(self.store.ro_connection(), transaction_id)
    }

    /// Durable materialization journal of a batch (recovery/inspection view).
    pub fn journal(
        &self,
        transaction_id: &str,
    ) -> Result<Vec<MaterializationRecord>, TransformError> {
        materializer::journal_records(self.store.ro_connection(), transaction_id)
    }

    /// Apply every pending journal entry, in publication order.
    ///
    /// Also the **crash-recovery entry point**: call it on a freshly opened
    /// store to resume batches interrupted at any point. It is idempotent —
    /// files already holding their committed bytes are counted as
    /// `already_current` and not rewritten — and a per-file conflict returns
    /// [`TransformError::MaterializationConflict`] while leaving the batch
    /// committed and its progress durable for a later retry.
    pub fn materialize_pending(&mut self) -> Result<MaterializationSummary, TransformError> {
        materializer::materialize_pending(self.store, &self.workspace_root)
    }

    /// Canonical identity + content hash of a proposal; the twin of the
    /// stored `transaction_id` (same id ⇒ same hash ⇒ idempotent replay).
    fn proposal_hash(proposal: &MultiFileProposal, prepared: &[PreparedChange]) -> String {
        let mut hasher = Sha256::new();
        for part in [
            proposal.transaction_id.as_str(),
            proposal.task_id.as_str(),
            proposal.agent_id.as_str(),
        ] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        for change in prepared {
            hasher.update((change.path.len() as u64).to_le_bytes());
            hasher.update(change.path.as_bytes());
            let expected_revision = change
                .expectation
                .expected_revision
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default();
            hasher.update((expected_revision.len() as u64).to_le_bytes());
            hasher.update(expected_revision.as_bytes());
            let expected_checksum = change
                .expectation
                .expected_checksum
                .as_deref()
                .unwrap_or_default();
            hasher.update((expected_checksum.len() as u64).to_le_bytes());
            hasher.update(expected_checksum.as_bytes());
            hasher.update(change.checksum.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Read a manifest (from an open connection — usable inside a publication
    /// transaction for idempotent replay).
    fn manifest_conn(
        conn: &rusqlite::Connection,
        transaction_id: &str,
    ) -> Result<TransactionManifest, TransformError> {
        let row: Option<(String, String, String, String, Option<String>)> = conn
            .query_row(
                "SELECT task_id, agent_id, state, committed_at, materialized_at
                 FROM transform_transactions WHERE transaction_id = ?1",
                [transaction_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (task_id, agent_id, state, committed_at, materialized_at) =
            row.ok_or_else(|| TransformError::TransactionNotFound(transaction_id.to_owned()))?;

        let mut statement = conn.prepare(
            "SELECT j.ordinal, j.artifact_id, j.revision_id, j.status,
                    r.content_hash, r.size_bytes
             FROM materialization_journal j
             JOIN artifact_revisions r ON r.revision_id = j.revision_id
             WHERE j.transaction_id = ?1
             ORDER BY j.ordinal ASC",
        )?;
        let rows = statement.query_map([transaction_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, u64>(5)?,
            ))
        })?;
        let mut changes = Vec::new();
        for row in rows {
            let (ordinal, artifact_id, revision_id, status, checksum, size_bytes) = row?;
            changes.push(CommittedChange {
                ordinal,
                artifact_id,
                revision_id: RevisionId::from_str(&revision_id)?,
                checksum,
                size_bytes,
                materialized: status == "materialized",
            });
        }

        Ok(TransactionManifest {
            transaction_id: transaction_id.to_owned(),
            task_id,
            agent_id,
            state: TransactionState::from_db(&state)?,
            committed_at: parse_timestamp(&committed_at)?,
            materialized_at: materialized_at
                .as_deref()
                .map(parse_timestamp)
                .transpose()?,
            changes,
        })
    }
}

fn parse_timestamp(raw: &str) -> Result<DateTime<Utc>, TransformError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| TransformError::InvalidTimestamp(raw.to_owned()))
}
