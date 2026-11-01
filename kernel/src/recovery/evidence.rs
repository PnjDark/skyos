//! Phase 6.0 — Probe-driven evidence for reconciliation.
//!
//! The Phase 5 reconciler accepted an `EffectObserved` / `EffectAbsent` verdict
//! from its caller. This module replaces that with an observation contract:
//!
//! * a caller names **what to observe** ([`EvidenceSpec`]);
//! * a registered [`EvidenceProbe`] collects **facts** from the world;
//! * the runtime derives the **verdict** itself ([`evaluate`]).
//!
//! A caller can therefore choose which fact to check, but never what it says.
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// The family of observable evidence. Used to select a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Commits in a Git repository relative to a recorded baseline.
    GitCommit,
    /// Bytes on disk compared against an expected digest.
    FileChecksum,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitCommit => "GitCommit",
            Self::FileChecksum => "FileChecksum",
        }
    }
}

impl TryFrom<&str> for EvidenceKind {
    type Error = ProbeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "GitCommit" => Ok(Self::GitCommit),
            "FileChecksum" => Ok(Self::FileChecksum),
            other => Err(ProbeError::Invalid(format!(
                "unknown evidence kind '{other}'"
            ))),
        }
    }
}

/// What the caller asks the runtime to observe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSpec {
    /// Look for a commit whose subject matches the recorded intent, in the
    /// range `baseline_commit..HEAD`.
    GitCommitAfterBaseline {
        repo_root: PathBuf,
        baseline_commit: String,
        intent_message: String,
    },
    /// Compare `path` against an expected SHA-256.
    FileChecksum {
        path: PathBuf,
        expected_sha256: String,
    },
}

impl EvidenceSpec {
    pub fn kind(&self) -> EvidenceKind {
        match self {
            Self::GitCommitAfterBaseline { .. } => EvidenceKind::GitCommit,
            Self::FileChecksum { .. } => EvidenceKind::FileChecksum,
        }
    }

    /// Human-readable description for the audit record.
    pub fn describe(&self) -> String {
        match self {
            Self::GitCommitAfterBaseline {
                repo_root,
                baseline_commit,
                intent_message,
            } => format!(
                "GitCommitAfterBaseline {{ repo: {}, baseline: {}, intent: {:?} }}",
                repo_root.display(),
                baseline_commit,
                intent_message
            ),
            Self::FileChecksum {
                path,
                expected_sha256,
            } => format!(
                "FileChecksum {{ path: {}, expected: {} }}",
                path.display(),
                expected_sha256
            ),
        }
    }
}

/// What the runtime knows when it asks for evidence.
#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub task_id: Uuid,
    pub step_number: usize,
    /// The pre-dispatch baseline the runtime recorded, if any. Probes must not
    /// substitute a caller-supplied baseline for this when one exists.
    pub recorded_baseline: Option<String>,
}

/// A fact gathered from the world. Deliberately raw: it is *not* a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    /// The command or read that produced this observation, for the audit trail.
    pub source: String,
    /// Structured observation. The runtime interprets this; callers do not.
    pub observed: serde_json::Value,
    pub collected_at: DateTime<Utc>,
}

impl EvidenceRef {
    pub fn new(kind: EvidenceKind, source: impl Into<String>, observed: serde_json::Value) -> Self {
        Self {
            kind,
            source: source.into(),
            observed,
            collected_at: Utc::now(),
        }
    }

    pub fn summary(&self) -> String {
        format!("{}: {}", self.source, self.observed)
    }
}

/// Collects facts. Implementations live in `tools`, where the mechanisms are.
pub trait EvidenceProbe: Send + Sync {
    fn kind(&self) -> EvidenceKind;
    fn probe(&self, spec: &EvidenceSpec, ctx: &ProbeContext) -> Result<EvidenceRef, ProbeError>;
}

#[derive(Debug, Error, Clone)]
pub enum ProbeError {
    #[error("evidence could not be collected: {0}")]
    Unavailable(String),
    #[error("evidence spec is invalid for this probe: {0}")]
    Invalid(String),
}

/// What the world shows. Produced only by [`evaluate`], never by a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationVerdict {
    /// The effect is present.
    ConfirmedSucceeded { evidence: EvidenceRef },
    /// The effect is provably absent; a retry may be authorized.
    ConfirmedNotExecuted { evidence: EvidenceRef },
    /// The evidence cannot distinguish the two; the task stays blocked.
    Indeterminate { reason: String },
}

impl ReconciliationVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfirmedSucceeded { .. } => "ConfirmedSucceeded",
            Self::ConfirmedNotExecuted { .. } => "ConfirmedNotExecuted",
            Self::Indeterminate { .. } => "Indeterminate",
        }
    }
}

/// Derive a verdict from an observation.
///
/// This is the only place a verdict is produced. The rules are deliberately
/// asymmetric: a probe can confirm that an effect happened, or prove it did not,
/// but anything ambiguous must resolve to `Indeterminate` — because
/// `ConfirmedNotExecuted` is the verdict that unlocks a retry.
pub fn evaluate(spec: &EvidenceSpec, evidence: &EvidenceRef) -> ReconciliationVerdict {
    if evidence.kind != spec.kind() {
        return ReconciliationVerdict::Indeterminate {
            reason: format!(
                "evidence kind {} does not match the requested {}",
                evidence.kind.as_str(),
                spec.kind().as_str()
            ),
        };
    }

    match spec {
        EvidenceSpec::GitCommitAfterBaseline { .. } => {
            let matching = evidence
                .observed
                .get("matching_commits")
                .and_then(|value| value.as_u64());

            match matching {
                Some(1) => ReconciliationVerdict::ConfirmedSucceeded {
                    evidence: evidence.clone(),
                },
                Some(0) => ReconciliationVerdict::ConfirmedNotExecuted {
                    evidence: evidence.clone(),
                },
                Some(other) => ReconciliationVerdict::Indeterminate {
                    reason: format!("{other} commits match the recorded intent; cannot attribute"),
                },
                None => ReconciliationVerdict::Indeterminate {
                    reason: "probe did not report a matching-commit count".to_string(),
                },
            }
        }

        EvidenceSpec::FileChecksum { .. } => {
            // A matching digest is proof of the effect. Anything else is not
            // proof of absence: the file may have been written and since
            // modified by something else.
            let matched = evidence
                .observed
                .get("match")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);

            if matched {
                ReconciliationVerdict::ConfirmedSucceeded {
                    evidence: evidence.clone(),
                }
            } else {
                ReconciliationVerdict::Indeterminate {
                    reason: "on-disk digest does not match; absence cannot be inferred".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn git_spec() -> EvidenceSpec {
        EvidenceSpec::GitCommitAfterBaseline {
            repo_root: PathBuf::from("/repo"),
            baseline_commit: "abc".into(),
            intent_message: "intent".into(),
        }
    }

    fn git_evidence(matching: u64) -> EvidenceRef {
        EvidenceRef::new(
            EvidenceKind::GitCommit,
            "git log",
            json!({ "matching_commits": matching }),
        )
    }

    #[test]
    fn one_matching_commit_confirms_success() {
        assert!(matches!(
            evaluate(&git_spec(), &git_evidence(1)),
            ReconciliationVerdict::ConfirmedSucceeded { .. }
        ));
    }

    #[test]
    fn zero_matching_commits_confirms_absence() {
        assert!(matches!(
            evaluate(&git_spec(), &git_evidence(0)),
            ReconciliationVerdict::ConfirmedNotExecuted { .. }
        ));
    }

    #[test]
    fn ambiguous_commit_counts_are_indeterminate() {
        assert!(matches!(
            evaluate(&git_spec(), &git_evidence(2)),
            ReconciliationVerdict::Indeterminate { .. }
        ));
    }

    #[test]
    fn a_probe_that_reports_nothing_is_indeterminate() {
        let evidence = EvidenceRef::new(EvidenceKind::GitCommit, "git log", json!({}));
        assert!(matches!(
            evaluate(&git_spec(), &evidence),
            ReconciliationVerdict::Indeterminate { .. }
        ));
    }

    #[test]
    fn a_checksum_mismatch_never_proves_absence() {
        let spec = EvidenceSpec::FileChecksum {
            path: PathBuf::from("/tmp/x"),
            expected_sha256: "deadbeef".into(),
        };
        let mismatch = EvidenceRef::new(
            EvidenceKind::FileChecksum,
            "sha256",
            json!({ "match": false, "actual": "cafe" }),
        );
        let observed = EvidenceRef::new(
            EvidenceKind::FileChecksum,
            "sha256",
            json!({ "match": true, "actual": "deadbeef" }),
        );

        assert!(matches!(
            evaluate(&spec, &mismatch),
            ReconciliationVerdict::Indeterminate { .. }
        ));
        assert!(matches!(
            evaluate(&spec, &observed),
            ReconciliationVerdict::ConfirmedSucceeded { .. }
        ));
    }

    #[test]
    fn mismatched_evidence_kind_is_indeterminate() {
        let evidence =
            EvidenceRef::new(EvidenceKind::FileChecksum, "sha256", json!({"match": true}));
        assert!(matches!(
            evaluate(&git_spec(), &evidence),
            ReconciliationVerdict::Indeterminate { .. }
        ));
    }
}
