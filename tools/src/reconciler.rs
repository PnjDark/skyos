//! Phase 6.0 — Evidence probes for governed reconciliation.
//!
//! The kernel owns the *verdict*; this module owns the *observation*. A probe
//! reads the world and reports facts. It never claims that an operation
//! succeeded or failed — that decision belongs to
//! `kernel::recovery::evidence::evaluate`, which sees only the observation.
//!
//! Probes are registered explicitly by the host. A runtime with no probe for a
//! requested evidence kind refuses to reconcile rather than defaulting.
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use kernel::recovery::evidence::{
    EvidenceKind, EvidenceProbe, EvidenceRef, EvidenceSpec, ProbeContext, ProbeError,
};
use serde_json::json;

/// Observes commits in a Git repository relative to a recorded baseline.
///
/// The baseline is chosen by the caller but cross-checked by the engine against
/// the value the runtime recorded before dispatch; this probe only reports what
/// the repository currently contains.
pub struct GitCommitProbe;

impl EvidenceProbe for GitCommitProbe {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::GitCommit
    }

    fn probe(&self, spec: &EvidenceSpec, _ctx: &ProbeContext) -> Result<EvidenceRef, ProbeError> {
        let EvidenceSpec::GitCommitAfterBaseline {
            repo_root,
            baseline_commit,
            intent_message,
        } = spec
        else {
            return Err(ProbeError::Invalid(
                "GitCommitProbe received a non-git evidence spec".to_string(),
            ));
        };

        let range = format!("{baseline_commit}..HEAD");
        let output = Command::new("git")
            .args(["log", "--format=%H%x1f%s", &range])
            .current_dir(repo_root)
            .output()
            .map_err(|error| ProbeError::Unavailable(format!("could not run git: {error}")))?;

        if !output.status.success() {
            return Err(ProbeError::Unavailable(format!(
                "git log {range} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let matches: Vec<(&str, &str)> = stdout
            .lines()
            .filter_map(|line| line.split_once('\x1f'))
            .filter(|(_, subject)| *subject == intent_message)
            .collect();

        Ok(EvidenceRef::new(
            EvidenceKind::GitCommit,
            format!("git log --format=%H%x1f%s {range}"),
            json!({
                "repo_root": repo_root,
                "baseline_commit": baseline_commit,
                "range": range,
                "intent_message": intent_message,
                "matching_commits": matches.len(),
                "commits": matches.iter().map(|(hash, _)| *hash).collect::<Vec<_>>(),
            }),
        ))
    }
}

/// Compares a file's bytes against an expected SHA-256.
///
/// A match confirms the effect; a mismatch is *not* proof of absence (the file
/// may have been written and later changed), so the engine resolves that case
/// to `Indeterminate`.
pub struct FileChecksumProbe;

impl EvidenceProbe for FileChecksumProbe {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::FileChecksum
    }

    fn probe(&self, spec: &EvidenceSpec, _ctx: &ProbeContext) -> Result<EvidenceRef, ProbeError> {
        let EvidenceSpec::FileChecksum {
            path,
            expected_sha256,
        } = spec
        else {
            return Err(ProbeError::Invalid(
                "FileChecksumProbe received a non-checksum evidence spec".to_string(),
            ));
        };

        let observed = match std::fs::read(path) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                json!({
                    "path": path,
                    "exists": true,
                    "size_bytes": bytes.len(),
                    "expected": expected_sha256,
                    "actual": actual,
                    "match": &actual == expected_sha256,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({
                "path": path,
                "exists": false,
                "expected": expected_sha256,
                "match": false,
            }),
            Err(error) => {
                return Err(ProbeError::Unavailable(format!(
                    "could not read {}: {error}",
                    path.display()
                )))
            }
        };

        Ok(EvidenceRef::new(
            EvidenceKind::FileChecksum,
            format!("sha256({})", path.display()),
            observed,
        ))
    }
}

/// The probes a full runtime should register. Missing any of them only disables
/// that evidence kind; reconciliation of the others is unaffected.
pub fn default_probes() -> Vec<Arc<dyn EvidenceProbe>> {
    vec![Arc::new(GitCommitProbe), Arc::new(FileChecksumProbe)]
}

/// Extract the repository HEAD so it can be recorded before dispatch.
///
/// Returns `None` when the path is not a readable Git repository; callers must
/// treat that as "no baseline recorded" rather than inventing one.
pub fn git_head(repo_root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git required for probe tests");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn repo() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        git(path, &["init"]);
        git(path, &["config", "user.name", "Probe Test"]);
        git(path, &["config", "user.email", "probe@sky.invalid"]);
        std::fs::write(path.join("a.txt"), "a").unwrap();
        git(path, &["add", "--", "a.txt"]);
        git(path, &["commit", "-m", "baseline"]);
        let baseline = git_head(path).unwrap();
        (dir, baseline)
    }

    fn ctx() -> ProbeContext {
        ProbeContext {
            task_id: uuid::Uuid::new_v4(),
            step_number: 0,
            recorded_baseline: None,
        }
    }

    #[test]
    fn reports_zero_matches_when_nothing_landed() {
        let (dir, baseline) = repo();
        let spec = EvidenceSpec::GitCommitAfterBaseline {
            repo_root: dir.path().to_path_buf(),
            baseline_commit: baseline,
            intent_message: "intended change".into(),
        };

        let evidence = GitCommitProbe.probe(&spec, &ctx()).unwrap();
        assert_eq!(evidence.observed["matching_commits"], 0);
    }

    #[test]
    fn reports_the_matching_commit_when_it_exists() {
        let (dir, baseline) = repo();
        std::fs::write(dir.path().join("b.txt"), "b").unwrap();
        git(dir.path(), &["add", "--", "b.txt"]);
        git(dir.path(), &["commit", "-m", "intended change"]);
        let head = git_head(dir.path()).unwrap();

        let spec = EvidenceSpec::GitCommitAfterBaseline {
            repo_root: dir.path().to_path_buf(),
            baseline_commit: baseline,
            intent_message: "intended change".into(),
        };

        let evidence = GitCommitProbe.probe(&spec, &ctx()).unwrap();
        assert_eq!(evidence.observed["matching_commits"], 1);
        assert_eq!(evidence.observed["commits"][0], head);
    }

    #[test]
    fn unreadable_repository_is_an_error_not_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let spec = EvidenceSpec::GitCommitAfterBaseline {
            repo_root: dir.path().to_path_buf(),
            baseline_commit: "deadbeef".into(),
            intent_message: "x".into(),
        };

        let error = GitCommitProbe.probe(&spec, &ctx()).unwrap_err();
        assert!(matches!(error, ProbeError::Unavailable(_)));
    }

    #[test]
    fn checksum_probe_reports_a_match_without_claiming_absence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"hello").unwrap();
        let digest = sha256_hex(b"hello");

        let matching = EvidenceSpec::FileChecksum {
            path: path.clone(),
            expected_sha256: digest,
        };
        let evidence = FileChecksumProbe.probe(&matching, &ctx()).unwrap();
        assert_eq!(evidence.observed["match"], true);

        let mismatching = EvidenceSpec::FileChecksum {
            path: path.clone(),
            expected_sha256: "0000".into(),
        };
        let evidence = FileChecksumProbe.probe(&mismatching, &ctx()).unwrap();
        assert_eq!(evidence.observed["match"], false);

        let missing = EvidenceSpec::FileChecksum {
            path: dir.path().join("absent.bin"),
            expected_sha256: "0000".into(),
        };
        let evidence = FileChecksumProbe.probe(&missing, &ctx()).unwrap();
        assert_eq!(evidence.observed["exists"], false);
    }
}
