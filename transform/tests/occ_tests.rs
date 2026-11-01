//! Phase 3B.2 — OCC expectation validation and single-winner commits.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use skyos_transform::{
    ArtifactRevisionStore, OccEngine, ProposedChange, RevisionExpectation, RevisionId,
    TransformError,
};
use tempfile::TempDir;

const NONE: &str = "<none>";

struct Harness {
    _temp: TempDir,
    db: PathBuf,
    store_root: PathBuf,
}

fn harness() -> Harness {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("runtime_state.db");
    let store_root = temp.path().join("artifacts");
    Harness {
        _temp: temp,
        db,
        store_root,
    }
}

impl Harness {
    fn store(&self) -> ArtifactRevisionStore {
        ArtifactRevisionStore::open(&self.db, &self.store_root).unwrap()
    }
}

/// A change whose expectation names the same artifact as its path (path is
/// the canonical artifact identity in this store).
fn change(
    path: &str,
    expected_revision: Option<RevisionId>,
    expected_checksum: Option<String>,
    content: &[u8],
) -> ProposedChange {
    ProposedChange {
        path: path.to_owned(),
        expectation: RevisionExpectation {
            artifact_id: path.to_owned(),
            expected_revision,
            expected_checksum,
        },
        content: content.to_vec(),
    }
}

fn assert_conflict(
    result: Result<skyos_transform::ArtifactRevision, TransformError>,
) -> TransformError {
    match result {
        Err(err @ TransformError::MergeConflict { .. }) => err,
        Err(other) => panic!("expected MergeConflict, got {other:?}"),
        Ok(rev) => panic!("expected MergeConflict, but commit succeeded as {}", rev.id),
    }
}

#[test]
fn first_write_on_empty_artifact_is_accepted() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);

    let revision = engine
        .commit_change(
            &change("docs/spec.md", None, None, b"v1"),
            "task-1",
            "agent-a",
        )
        .unwrap();

    assert!(revision.parent_id.is_none());
    let head = store.head("docs/spec.md").unwrap().unwrap();
    assert_eq!(head.id, revision.id);
    assert_eq!(store.revisions_for("docs/spec.md").unwrap().len(), 1);
}

#[test]
fn first_write_when_head_exists_conflicts() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let first = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-2", "agent-a")
        .unwrap();

    let err = assert_conflict(engine.commit_change(
        &change("a.txt", None, None, b"v2"),
        "task-2",
        "agent-b",
    ));
    match err {
        TransformError::MergeConflict {
            expected_revision,
            actual_revision,
            ref reason,
            ..
        } => {
            assert_eq!(expected_revision, NONE);
            assert_eq!(actual_revision, first.id.to_string());
            assert!(reason.contains("first write"), "reason: {reason}");
        }
        other => panic!("expected MergeConflict, got {other:?}"),
    }
    // Rejected proposal changed nothing.
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, first.id);
}

#[test]
fn matching_revision_and_checksum_commits() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-3", "agent-a")
        .unwrap();

    let next = engine
        .commit_change(
            &change(
                "a.txt",
                Some(base.id.clone()),
                Some(base.checksum.clone()),
                b"v2",
            ),
            "task-3",
            "agent-b",
        )
        .unwrap();

    assert_eq!(next.parent_id, Some(base.id.clone()));
    let head = store.head("a.txt").unwrap().unwrap();
    assert_eq!(head.id, next.id);
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 2);
    // The committed content is the proposed content, hash-verified.
    assert_eq!(store.read_content(next.id.as_str()).unwrap(), b"v2");
}

#[test]
fn stale_revision_conflicts_and_reports_actual_head() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-4", "agent-a")
        .unwrap();
    let current = engine
        .commit_change(
            &change("a.txt", Some(base.id.clone()), None, b"v2"),
            "task-4",
            "agent-a",
        )
        .unwrap();

    // Caller still believes `base` is the head.
    let err = assert_conflict(engine.commit_change(
        &change("a.txt", Some(base.id.clone()), None, b"stale"),
        "task-4",
        "agent-b",
    ));
    match err {
        TransformError::MergeConflict {
            ref expected_revision,
            ref actual_revision,
            ref reason,
            ..
        } => {
            assert_eq!(expected_revision, &base.id.to_string());
            assert_eq!(actual_revision, current.id.to_string().as_str());
            assert!(reason.contains("stale"), "reason: {reason}");
        }
        other => panic!("expected MergeConflict, got {other:?}"),
    }
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 2);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, current.id);
}

#[test]
fn matching_revision_with_wrong_checksum_conflicts() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-5", "agent-a")
        .unwrap();

    let wrong = "0".repeat(64);
    let err = assert_conflict(engine.commit_change(
        &change("a.txt", Some(base.id.clone()), Some(wrong), b"v2"),
        "task-5",
        "agent-b",
    ));
    match err {
        TransformError::MergeConflict {
            ref expected_revision,
            ref actual_revision,
            ref reason,
            ..
        } => {
            assert_eq!(expected_revision, &base.id.to_string());
            assert_eq!(actual_revision, &base.id.to_string());
            assert!(reason.contains("checksum"), "reason: {reason}");
        }
        other => panic!("expected MergeConflict, got {other:?}"),
    }
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
}

#[test]
fn expected_revision_with_no_head_conflicts() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);

    let phantom = RevisionId::new();
    let err = assert_conflict(engine.commit_change(
        &change("ghost.txt", Some(phantom.clone()), None, b"content"),
        "task-6",
        "agent-a",
    ));
    match err {
        TransformError::MergeConflict {
            ref expected_revision,
            ref actual_revision,
            ..
        } => {
            assert_eq!(expected_revision, &phantom.to_string());
            assert_eq!(actual_revision, NONE);
        }
        other => panic!("expected MergeConflict, got {other:?}"),
    }
    // Nothing was created for the failed proposal.
    assert!(store.head("ghost.txt").unwrap().is_none());
    assert!(store.revisions_for("ghost.txt").unwrap().is_empty());
}

#[test]
fn checksum_without_expected_revision_is_inconsistent() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);

    let result = engine.commit_change(
        &change("a.txt", None, Some("0".repeat(64)), b"v1"),
        "task-7",
        "agent-a",
    );
    match result {
        Err(TransformError::InconsistentExpectation { ref reason, .. }) => {
            assert!(reason.contains("checksum"), "reason: {reason}");
        }
        other => panic!("expected InconsistentExpectation, got {other:?}"),
    }
    assert!(store.head("a.txt").unwrap().is_none());
}

#[test]
fn expectation_naming_a_different_artifact_is_rejected() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);

    // Path is the canonical artifact identity; an expectation that names a
    // different artifact must not be silently re-keyed to the path.
    let mismatched = ProposedChange {
        path: "a.txt".to_owned(),
        expectation: RevisionExpectation {
            artifact_id: "b.txt".to_owned(),
            expected_revision: None,
            expected_checksum: None,
        },
        content: b"v1".to_vec(),
    };
    let result = engine.commit_change(&mismatched, "task-8", "agent-a");
    match result {
        Err(TransformError::InconsistentExpectation { ref reason, .. }) => {
            assert!(reason.contains("b.txt"), "reason: {reason}");
            assert!(reason.contains("a.txt"), "reason: {reason}");
        }
        other => panic!("expected InconsistentExpectation, got {other:?}"),
    }
    assert!(store.head("a.txt").unwrap().is_none());
}

#[test]
fn failed_proposal_creates_no_revision_and_does_not_move_head() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-9", "agent-a")
        .unwrap();
    let current = engine
        .commit_change(
            &change("a.txt", Some(base.id.clone()), None, b"v2"),
            "task-9",
            "agent-a",
        )
        .unwrap();

    // Stale proposal fails...
    assert_conflict(engine.commit_change(
        &change("a.txt", Some(base.id.clone()), None, b"should-not-land"),
        "task-9",
        "agent-b",
    ));

    // ...and left no trace: same revision count, same head, same content.
    let history = store.revisions_for("a.txt").unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, current.id);
    assert_eq!(store.read_content(current.id.as_str()).unwrap(), b"v2");
}

#[test]
fn retry_after_success_conflicts_instead_of_silently_succeeding() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-10", "agent-a")
        .unwrap();

    let proposal = change("a.txt", Some(base.id.clone()), None, b"v2");
    let first = engine
        .commit_change(&proposal, "task-10", "agent-a")
        .unwrap();

    // Exact retry: explicit semantics are conflict-plus-new-head, not a
    // duplicate revision and not a silent success.
    let err = assert_conflict(engine.commit_change(&proposal, "task-10", "agent-a"));
    match err {
        TransformError::MergeConflict {
            ref actual_revision,
            ..
        } => assert_eq!(actual_revision, &first.id.to_string()),
        other => panic!("expected MergeConflict, got {other:?}"),
    }
    let history = store.revisions_for("a.txt").unwrap();
    assert_eq!(history.len(), 2, "retry must not create a second revision");
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, first.id);
}

#[test]
fn dry_run_preflight_reports_without_mutating() {
    let h = harness();
    let mut store = h.store();
    let mut engine = OccEngine::new(&mut store);
    let base = engine
        .commit_change(&change("a.txt", None, None, b"v1"), "task-11", "agent-a")
        .unwrap();

    // Current expectation passes the preflight...
    engine
        .validate_expectation_dry_run(&change(
            "a.txt",
            Some(base.id.clone()),
            Some(base.checksum.clone()),
            b"v2",
        ))
        .unwrap();

    // ...a stale one fails it...
    let stale =
        engine.validate_expectation_dry_run(&change("a.txt", Some(RevisionId::new()), None, b"v2"));
    assert!(matches!(stale, Err(TransformError::MergeConflict { .. })));

    // ...and neither preflight touched storage.
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, base.id);
}

#[derive(Debug)]
enum Outcome {
    Won {
        revision: String,
        parent: Option<String>,
    },
    Lost {
        actual_revision: String,
    },
    OtherError(String),
}

#[test]
fn concurrent_proposals_from_same_base_have_exactly_one_winner() {
    let h = harness();
    let mut store = h.store();
    let base = {
        let mut engine = OccEngine::new(&mut store);
        engine
            .commit_change(
                &change("hot.txt", None, None, b"base"),
                "task-12",
                "agent-seed",
            )
            .unwrap()
    };

    let threads = 6usize;
    let barrier = Arc::new(Barrier::new(threads));
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::new();
    for t in 0..threads {
        let db = h.db.clone();
        let store_root = h.store_root.clone();
        let barrier = barrier.clone();
        let tx = tx.clone();
        let expected = base.id.clone();
        let expected_checksum = base.checksum.clone();
        handles.push(thread::spawn(move || {
            let mut store = ArtifactRevisionStore::open(&db, &store_root).unwrap();
            let mut engine = OccEngine::new(&mut store);
            let proposal = change(
                "hot.txt",
                Some(expected),
                Some(expected_checksum),
                format!("candidate-{t}").as_bytes(),
            );

            // Release every committer at once so they race the same base.
            barrier.wait();

            let outcome = match engine.commit_change(&proposal, "task-12", &format!("agent-{t}")) {
                Ok(revision) => Outcome::Won {
                    revision: revision.id.to_string(),
                    parent: revision.parent_id.map(|p| p.to_string()),
                },
                Err(TransformError::MergeConflict {
                    actual_revision, ..
                }) => Outcome::Lost { actual_revision },
                Err(other) => Outcome::OtherError(other.to_string()),
            };
            tx.send(outcome).unwrap();
        }));
    }
    drop(tx);
    for handle in handles {
        handle.join().unwrap();
    }

    let outcomes: Vec<Outcome> = rx.iter().collect();
    assert_eq!(
        outcomes.len(),
        threads,
        "every thread must report an outcome"
    );

    let winners: Vec<(String, Option<String>)> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Won { revision, parent } => Some((revision.clone(), parent.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(winners.len(), 1, "exactly one proposal may win");
    let (winner_id, winner_parent) = winners.into_iter().next().unwrap();
    assert_eq!(winner_parent, Some(base.id.to_string()));

    // Every loser reports the actual current head — the winner's revision.
    let mut losses = 0usize;
    for outcome in &outcomes {
        match outcome {
            Outcome::Won { .. } => {}
            Outcome::Lost { actual_revision } => {
                assert_eq!(actual_revision, &winner_id);
                losses += 1;
            }
            Outcome::OtherError(err) => panic!("non-conflict failure: {err}"),
        }
    }
    assert_eq!(losses, threads - 1);

    // Verify durable state, not just return values: seed + exactly one winner
    // in history, head is the winner, parent chain intact, content intact.
    let history = store.revisions_for("hot.txt").unwrap();
    assert_eq!(history.len(), 2, "losers must not create revisions");
    let head = store.head("hot.txt").unwrap().expect("head must exist");
    assert_eq!(head.id.to_string(), winner_id);
    assert_eq!(head.parent_id, Some(base.id.clone()));
    for revision in &history {
        if let Some(parent) = &revision.parent_id {
            assert!(store.get_revision(parent.as_str()).is_ok());
        }
        assert!(store.read_content(revision.id.as_str()).is_ok());
    }
}
