//! `skyos-transform` — immutable artifact revisions and optimistic
//! concurrency control for governed workspace transformation (Phase 3B).
//!
//! Stage 3B.1: typed revision models and the content-addressed revision
//! store. Blob bytes are persisted through the kernel `ArtifactRegistry`;
//! revision metadata and per-artifact head pointers live in transform-owned
//! tables inside the same runtime database.
//!
//! Stage 3B.2: optimistic concurrency control (`occ`). Expectation validation
//! and head promotion form one atomic operation, so concurrent proposals from
//! the same base have exactly one winner.
//!
//! Stage 3B.3: atomic multi-file transaction publication (`transaction`) and
//! replayable filesystem materialization (`materializer`). A batch's manifest,
//! revisions, head promotions and recovery journal commit in one SQLite
//! transaction; files are then applied per-entry with crash recovery.

pub mod materializer;
pub mod models;
pub mod occ;
pub mod store;
pub mod transaction;

pub use materializer::MaterializationSummary;
pub use models::{
    ArtifactRevision, CommittedChange, MaterializationRecord, MaterializationStatus,
    MultiFileProposal, ProposedChange, RevisionExpectation, RevisionId, TransactionManifest,
    TransactionState, TransformError,
};
pub use occ::OccEngine;
pub use store::ArtifactRevisionStore;
pub use transaction::TransactionEngine;
