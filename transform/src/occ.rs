//! Phase 3B.2 — optimistic concurrency control for governed workspace
//! transformation.
//!
//! The single-winner guarantee is enforced by
//! [`ArtifactRevisionStore::append_if_head_matches`], which evaluates the
//! caller's `RevisionExpectation` against the head read inside the same
//! SQLite `IMMEDIATE` transaction that inserts the revision and promotes the
//! head. [`OccEngine`] is the façade over that commit protocol, plus a
//! non-mutating preflight for better early feedback.

use crate::models::{ArtifactRevision, ProposedChange, TransformError};
use crate::store::ArtifactRevisionStore;

/// OCC façade over an [`ArtifactRevisionStore`].
pub struct OccEngine<'a> {
    store: &'a mut ArtifactRevisionStore,
}

impl<'a> OccEngine<'a> {
    pub fn new(store: &'a mut ArtifactRevisionStore) -> Self {
        Self { store }
    }

    /// Evaluate the change's expectation against the currently visible head
    /// without mutating anything.
    ///
    /// This is a **preflight aid only**: the head is read outside any write
    /// transaction, so another committer can move it immediately afterwards.
    /// Correctness comes exclusively from `commit_change`, which re-validates
    /// the expectation atomically with the head promotion.
    pub fn validate_expectation_dry_run(
        &self,
        change: &ProposedChange,
    ) -> Result<(), TransformError> {
        let head = self.store.head(&change.path)?;
        ArtifactRevisionStore::evaluate_expectation(
            &change.path,
            &change.expectation,
            head.as_ref(),
        )
    }

    /// Atomically validate `change`'s expectation and, only if it still holds,
    /// append the new revision and promote it to head as one operation.
    ///
    /// Of two proposals based on the same head, exactly one succeeds; the
    /// other returns [`TransformError::MergeConflict`] reporting the actual
    /// current head (the winner). A rejected proposal creates no revision and
    /// moves no head pointer.
    ///
    /// **Retry semantics:** this call is not implicitly idempotent. Retrying a
    /// change after it has already succeeded re-validates against the head it
    /// just moved, so the retry reports a `MergeConflict` carrying the new
    /// head instead of silently succeeding. Callers re-read the head and
    /// rebase, or layer explicit idempotency keys on top (Phase 3B.3's
    /// transaction ids provide exactly that for multi-file proposals).
    pub fn commit_change(
        &mut self,
        change: &ProposedChange,
        task_id: &str,
        agent_id: &str,
    ) -> Result<ArtifactRevision, TransformError> {
        self.store.append_if_head_matches(change, task_id, agent_id)
    }
}
