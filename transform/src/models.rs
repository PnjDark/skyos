use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Typed, immutable revision identifier (UUIDv4).
///
/// A newtype instead of a bare `String` so arbitrary user-supplied strings
/// cannot masquerade as revision handles anywhere in the transform API.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevisionId(String);

impl RevisionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RevisionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RevisionId {
    type Err = TransformError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(|_| Self(s.to_owned()))
            .map_err(|_| TransformError::InvalidRevisionId(s.to_owned()))
    }
}

/// One immutable point in an artifact's revision DAG.
///
/// `checksum` is always the SHA-256 of the exact stored bytes, recomputed by
/// the store — never trusted from a caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRevision {
    pub id: RevisionId,
    /// Canonical artifact key (workspace-relative canonical path string).
    pub artifact_id: String,
    pub parent_id: Option<RevisionId>,
    pub checksum: String,
    pub task_id: String,
    pub committed_by_agent: String,
    pub size_bytes: u64,
    pub committed_at: DateTime<Utc>,
}

/// Caller's belief about the current head of an artifact.
///
/// `expected_revision: None` means "I believe this artifact has no head"
/// (first write). `expected_checksum: None` means the caller does not pin
/// content, only the revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionExpectation {
    pub artifact_id: String,
    pub expected_revision: Option<RevisionId>,
    pub expected_checksum: Option<String>,
}

/// A single file change proposed against a known base revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedChange {
    pub path: String,
    pub expectation: RevisionExpectation,
    pub content: Vec<u8>,
}

/// A bounded set of changes committed together under one transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiFileProposal {
    pub transaction_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub changes: Vec<ProposedChange>,
}

/// Lifecycle of a published batch's *materialization* (3B.3). Metadata
/// publication is atomic; file replacement is not, so `Committed` means
/// "revisions and heads are durable, some workspace files may still need
/// writing" — never that the workspace already shows the new bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionState {
    /// Manifest committed; materialization may be incomplete or not started.
    Committed,
    /// Every journal entry verified on disk.
    Materialized,
}

impl TransactionState {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Materialized => "materialized",
        }
    }

    pub(crate) fn from_db(raw: &str) -> Result<Self, TransformError> {
        match raw {
            "committed" => Ok(Self::Committed),
            "materialized" => Ok(Self::Materialized),
            other => Err(TransformError::InvalidTransactionState(other.to_owned())),
        }
    }
}

/// One change inside a committed transaction manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedChange {
    pub ordinal: i64,
    /// Canonical artifact key (workspace-relative path, `/`-separated).
    pub artifact_id: String,
    pub revision_id: RevisionId,
    pub checksum: String,
    pub size_bytes: u64,
    /// Whether this change's bytes are verified on disk.
    pub materialized: bool,
}

/// The durable record of a published batch: its identity, lifecycle state,
/// and the committed revisions it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionManifest {
    pub transaction_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub state: TransactionState,
    pub committed_at: DateTime<Utc>,
    pub materialized_at: Option<DateTime<Utc>>,
    pub changes: Vec<CommittedChange>,
}

/// Per-file materialization progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationStatus {
    /// Committed bytes not yet verified on disk (or completion lost).
    Pending,
    /// File verified to hold the committed bytes.
    Materialized,
}

impl MaterializationStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Materialized => "materialized",
        }
    }

    pub(crate) fn from_db(raw: &str) -> Result<Self, TransformError> {
        match raw {
            "pending" => Ok(Self::Pending),
            "materialized" => Ok(Self::Materialized),
            other => Err(TransformError::InvalidTransactionState(other.to_owned())),
        }
    }
}

/// One durable journal row: the recovery record written in the *same*
/// database transaction as its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationRecord {
    pub transaction_id: String,
    pub ordinal: i64,
    pub artifact_id: String,
    pub revision_id: RevisionId,
    pub status: MaterializationStatus,
    pub updated_at: DateTime<Utc>,
}

/// Transform-stage failures. `MergeConflict` and `DuplicatePath` are the
/// structured rejections OCC (3B.2) and the transaction layer (3B.3)
/// surface; the remaining variants back the 3B.1 revision store.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error(
        "merge conflict on {path}: expected revision {expected_revision}, current head is {actual_revision}: {reason}"
    )]
    MergeConflict {
        path: String,
        /// The revision the caller expected; `<none>` for a first write.
        expected_revision: String,
        /// The revision actually at the head when the check ran; `<none>` if
        /// no head exists. A losing concurrent proposal uses this to report
        /// the winner.
        actual_revision: String,
        /// Which expectation failed: stale head, first-write violation,
        /// missing head, or a checksum mismatch on the expected head.
        reason: String,
    },
    #[error("inconsistent expectation for {path}: {reason}")]
    InconsistentExpectation { path: String, reason: String },
    #[error("duplicate canonical path in proposal: {0}")]
    DuplicatePath(String),
    #[error("transaction id {transaction_id} already used by a different proposal: {reason}")]
    TransactionIdConflict {
        transaction_id: String,
        reason: String,
    },
    #[error("transaction not found: {0}")]
    TransactionNotFound(String),
    #[error("invalid proposal: {0}")]
    InvalidProposal(String),
    #[error("unsafe path rejected for {path}: {reason}")]
    UnsafePath { path: String, reason: String },
    #[error(
        "materialization conflict for {path}: {reason}; progress so far is durable, the batch stays committed"
    )]
    MaterializationConflict { path: String, reason: String },
    #[error("invalid transaction state in store: {0}")]
    InvalidTransactionState(String),
    #[error("revision not found: {0}")]
    RevisionNotFound(String),
    #[error(
        "checksum mismatch for revision {revision_id}: expected {expected}, calculated {calculated}"
    )]
    ChecksumMismatch {
        revision_id: String,
        expected: String,
        calculated: String,
    },
    #[error("content blob missing from store: {0}")]
    BlobMissing(String),
    #[error("invalid revision id: {0}")]
    InvalidRevisionId(String),
    #[error("invalid revision timestamp in store: {0}")]
    InvalidTimestamp(String),
    #[error("artifact registry error: {0}")]
    Registry(#[from] kernel::artifacts::registry::ArtifactError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
