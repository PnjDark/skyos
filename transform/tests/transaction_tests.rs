//! Phase 3B.3 — multi-file transaction publication, idempotency, concurrency
//! and crash recovery.

use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;

use skyos_transform::{
    ArtifactRevisionStore, MultiFileProposal, ProposedChange, RevisionExpectation, RevisionId,
    TransactionEngine, TransactionState, TransformError,
};
use tempfile::TempDir;

struct Harness {
    _temp: TempDir,
    db: PathBuf,
    store_root: PathBuf,
    workspace: PathBuf,
}

fn harness() -> Harness {
    let temp = TempDir::new().unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    Harness {
        db: temp.path().join("runtime_state.db"),
        store_root: temp.path().join("artifacts"),
        workspace,
        _temp: temp,
    }
}

impl Harness {
    fn store(&self) -> ArtifactRevisionStore {
        ArtifactRevisionStore::open(&self.db, &self.store_root).unwrap()
    }

    fn read_workspace(&self, relative: &str) -> Option<Vec<u8>> {
        let path = self.workspace.join(relative);
        if path.exists() {
            Some(std::fs::read(path).unwrap())
        } else {
            None
        }
    }

    /// Committed transaction rows for `ids` (direct SQL: durable state, not
    /// return values).
    fn transaction_rows(&self, ids: &[&str]) -> i64 {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        ids.iter()
            .map(|id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM transform_transactions WHERE transaction_id = ?1",
                    [id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
            })
            .sum()
    }

    fn journal_rows(&self, id: &str) -> i64 {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM materialization_journal WHERE transaction_id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn journal_status(&self, id: &str, ordinal: i64) -> String {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row(
            "SELECT status FROM materialization_journal
             WHERE transaction_id = ?1 AND ordinal = ?2",
            rusqlite::params![id, ordinal],
            |row| row.get(0),
        )
        .unwrap()
    }
}

fn first_write(path: &str, content: &str) -> ProposedChange {
    ProposedChange {
        path: path.to_owned(),
        expectation: RevisionExpectation {
            artifact_id: path.to_owned(),
            expected_revision: None,
            expected_checksum: None,
        },
        content: content.as_bytes().to_vec(),
    }
}

fn update(path: &str, base: &RevisionId, content: &str) -> ProposedChange {
    ProposedChange {
        path: path.to_owned(),
        expectation: RevisionExpectation {
            artifact_id: path.to_owned(),
            expected_revision: Some(base.clone()),
            expected_checksum: None,
        },
        content: content.as_bytes().to_vec(),
    }
}

fn proposal(id: &str, changes: Vec<ProposedChange>) -> MultiFileProposal {
    MultiFileProposal {
        transaction_id: id.to_owned(),
        task_id: "task-tx".to_owned(),
        agent_id: "agent-a".to_owned(),
        changes,
    }
}

/// Commit a batch and return its manifest (engine scoped so the store can be
/// queried afterwards).
fn commit(h: &Harness, p: &MultiFileProposal) -> skyos_transform::TransactionManifest {
    let mut store = h.store();
    let mut engine = TransactionEngine::new(&mut store, &h.workspace);
    engine.commit(p).unwrap()
}

fn commit_result(
    h: &Harness,
    p: &MultiFileProposal,
) -> Result<skyos_transform::TransactionManifest, TransformError> {
    let mut store = h.store();
    let mut engine = TransactionEngine::new(&mut store, &h.workspace);
    engine.commit(p)
}

fn materialize(h: &Harness) -> Result<skyos_transform::MaterializationSummary, TransformError> {
    let mut store = h.store();
    let mut engine = TransactionEngine::new(&mut store, &h.workspace);
    engine.materialize_pending()
}

fn manifest_of(h: &Harness, id: &str) -> skyos_transform::TransactionManifest {
    let mut store = h.store();
    let engine = TransactionEngine::new(&mut store, &h.workspace);
    engine.manifest(id).unwrap()
}

// ---------------------------------------------------------------------------
// Atomic publication
// ---------------------------------------------------------------------------

#[test]
fn commit_publishes_manifest_revisions_heads_and_journal_together() {
    let h = harness();
    let p = proposal(
        "tx-1",
        vec![
            first_write("src/a.rs", "alpha"),
            first_write("src/b.rs", "beta"),
            first_write("docs/c.md", "gamma"),
        ],
    );
    let manifest = commit(&h, &p);

    assert_eq!(manifest.transaction_id, "tx-1");
    assert_eq!(manifest.state, TransactionState::Committed);
    assert_eq!(manifest.changes.len(), 3);
    assert_eq!(h.transaction_rows(&["tx-1"]), 1);
    assert_eq!(h.journal_rows("tx-1"), 3);

    let store = h.store();
    for change in &manifest.changes {
        assert!(!change.materialized, "nothing on disk until materialize");
        let head = store.head(&change.artifact_id).unwrap().unwrap();
        assert_eq!(head.id, change.revision_id);
        assert_eq!(head.checksum, change.checksum);
        assert!(head.parent_id.is_none());
        assert_eq!(store.revisions_for(&change.artifact_id).unwrap().len(), 1);
        let proposed = p
            .changes
            .iter()
            .find(|c| c.path == change.artifact_id)
            .unwrap();
        assert_eq!(
            change.checksum,
            ArtifactRevisionStore::checksum_of(&proposed.content)
        );
    }
    // Publication is metadata-only: no file has been touched yet.
    assert!(h.read_workspace("src/a.rs").is_none());
    assert!(h.read_workspace("src/b.rs").is_none());
    assert!(h.read_workspace("docs/c.md").is_none());

    let journal = manifest_of(&h, "tx-1").changes;
    assert_eq!(journal.len(), 3);
}

#[test]
fn materialize_writes_all_files_marks_batch_materialized_and_is_idempotent() {
    let h = harness();
    let p = proposal(
        "tx-2",
        vec![
            first_write("a.txt", "one"),
            first_write("sub/deep/b.txt", "two"),
            first_write("c.txt", "three"),
        ],
    );
    commit(&h, &p);

    let summary = materialize(&h).unwrap();
    assert_eq!(summary.applied, 3);
    assert_eq!(summary.already_current, 0);
    assert_eq!(summary.completed_transactions, vec!["tx-2".to_string()]);

    assert_eq!(h.read_workspace("a.txt").unwrap(), b"one");
    assert_eq!(h.read_workspace("sub/deep/b.txt").unwrap(), b"two");
    assert_eq!(h.read_workspace("c.txt").unwrap(), b"three");

    let manifest = manifest_of(&h, "tx-2");
    assert_eq!(manifest.state, TransactionState::Materialized);
    assert!(manifest.materialized_at.is_some());
    assert!(manifest.changes.iter().all(|c| c.materialized));

    // Second run is a no-op: no pending entries, nothing rewritten.
    let store = h.store();
    let head_before = store.head("a.txt").unwrap().unwrap().id;
    let summary = materialize(&h).unwrap();
    assert_eq!(summary.applied, 0);
    assert_eq!(summary.already_current, 0);
    assert!(summary.completed_transactions.is_empty());
    let store = h.store();
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, head_before);
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"one");
}

#[test]
fn stale_expectation_rolls_back_the_entire_batch() {
    let h = harness();

    // Seed A and move its head once, so we hold a genuinely stale base.
    commit(&h, &proposal("tx-seed", vec![first_write("a.txt", "v1")]));
    materialize(&h).unwrap();
    let store = h.store();
    let stale_base = store.head("a.txt").unwrap().unwrap().id;
    drop(store);
    commit(
        &h,
        &proposal("tx-move", vec![update("a.txt", &stale_base, "v2")]),
    );
    materialize(&h).unwrap();

    // Batch: stale change on A + a brand-new file B. Must publish nothing.
    let result = commit_result(
        &h,
        &proposal(
            "tx-stale",
            vec![
                update("a.txt", &stale_base, "v3"),
                first_write("b.txt", "new"),
            ],
        ),
    );
    match result {
        Err(TransformError::MergeConflict { ref path, .. }) => assert_eq!(path, "a.txt"),
        other => panic!("expected MergeConflict on a.txt, got {other:?}"),
    }

    // No manifest, no journal, no revisions, no head movement — anywhere.
    assert_eq!(h.transaction_rows(&["tx-stale"]), 0);
    assert_eq!(h.journal_rows("tx-stale"), 0);
    let store = h.store();
    let history = store.revisions_for("a.txt").unwrap();
    assert_eq!(history.len(), 2, "the stale batch must not add revisions");
    // Head is still the tx-move revision (second in history), not a new one.
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, history[1].id);
    assert!(store.head("b.txt").unwrap().is_none());
    assert!(store.revisions_for("b.txt").unwrap().is_empty());
    assert!(h.read_workspace("b.txt").is_none());
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"v2");
}

#[test]
fn duplicate_canonical_targets_are_rejected_before_publication() {
    let h = harness();

    let result = commit_result(
        &h,
        &proposal(
            "tx-dup",
            vec![
                first_write("dir/file.txt", "one"),
                first_write("dir/file.txt", "two"),
            ],
        ),
    );
    assert!(matches!(result, Err(TransformError::DuplicatePath(_))));

    // Same target spelled non-canonically still resolves to a rejected path
    // (non-canonical spelling) rather than sneaking past.
    let result = commit_result(
        &h,
        &proposal(
            "tx-dup2",
            vec![
                first_write("dir/file.txt", "one"),
                first_write("dir/./file.txt", "two"),
            ],
        ),
    );
    assert!(matches!(
        result,
        Err(TransformError::UnsafePath { .. }) | Err(TransformError::DuplicatePath(_))
    ));

    assert_eq!(h.transaction_rows(&["tx-dup", "tx-dup2"]), 0);
    let store = h.store();
    assert!(store.head("dir/file.txt").unwrap().is_none());
}

#[test]
fn unsafe_paths_are_rejected_before_publication() {
    let h = harness();

    for (id, path) in [
        ("tx-abs", "/etc/passwd"),
        ("tx-trav", "../outside.txt"),
        ("tx-trav2", "src/../../outside.txt"),
        ("tx-dot", "./a.txt"),
        ("tx-empty", ""),
    ] {
        let result = commit_result(&h, &proposal(id, vec![first_write(path, "payload")]));
        let rejected = matches!(
            result,
            Err(TransformError::UnsafePath { .. }) | Err(TransformError::InvalidProposal(_))
        );
        assert!(rejected, "path {path:?} must be rejected, got {result:?}");
    }
    assert_eq!(
        h.transaction_rows(&["tx-abs", "tx-trav", "tx-trav2", "tx-dot", "tx-empty"]),
        0
    );
    let store = h.store();
    assert!(store.head("a.txt").unwrap().is_none());
    assert!(store.head("etc/passwd").unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected_before_publication() {
    let h = harness();
    let outside = h._temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, h.workspace.join("link")).unwrap();

    let result = commit_result(
        &h,
        &proposal("tx-sym", vec![first_write("link/evil.txt", "x")]),
    );
    assert!(matches!(result, Err(TransformError::UnsafePath { .. })));
    assert_eq!(h.transaction_rows(&["tx-sym"]), 0);
}

#[cfg(windows)]
#[test]
fn junction_escape_is_rejected_before_publication() {
    let h = harness();
    let outside = h._temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    // Directory junctions need no privileges on Windows.
    let link = h.workspace.join("link").to_string_lossy().into_owned();
    let target = outside.to_string_lossy().into_owned();
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J", link.as_str(), target.as_str()])
        .status()
        .unwrap();
    assert!(status.success());

    let result = commit_result(
        &h,
        &proposal("tx-sym", vec![first_write("link/evil.txt", "x")]),
    );
    assert!(matches!(result, Err(TransformError::UnsafePath { .. })));
    assert_eq!(h.transaction_rows(&["tx-sym"]), 0);
}

// ---------------------------------------------------------------------------
// Transaction-id idempotency
// ---------------------------------------------------------------------------

#[test]
fn replaying_the_same_proposal_returns_the_existing_manifest() {
    let h = harness();
    let p = proposal(
        "tx-replay",
        vec![first_write("a.txt", "alpha"), first_write("b.txt", "beta")],
    );
    let first = commit(&h, &p);
    let replay = commit(&h, &p);

    assert_eq!(first, replay, "identical replay returns the same manifest");
    assert_eq!(h.transaction_rows(&["tx-replay"]), 1);

    let store = h.store();
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.revisions_for("b.txt").unwrap().len(), 1);
    assert_eq!(
        store.head("a.txt").unwrap().unwrap().id,
        first.changes[0].revision_id
    );
}

#[test]
fn reusing_a_transaction_id_with_different_content_conflicts() {
    let h = harness();
    let original = commit(&h, &proposal("tx-id", vec![first_write("a.txt", "alpha")]));
    let original_head = original.changes[0].revision_id.clone();

    let result = commit_result(
        &h,
        &proposal("tx-id", vec![first_write("a.txt", "different")]),
    );
    assert!(matches!(
        result,
        Err(TransformError::TransactionIdConflict { .. })
    ));

    // Original manifest and heads untouched; nothing new published.
    let manifest = manifest_of(&h, "tx-id");
    assert_eq!(manifest.changes[0].revision_id, original_head);
    assert_eq!(manifest.changes[0].checksum, original.changes[0].checksum);
    let store = h.store();
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, original_head);
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn concurrent_overlapping_batches_have_exactly_one_winner() {
    let h = harness();
    commit(
        &h,
        &proposal("tx-seed", vec![first_write("hot.txt", "base")]),
    );
    materialize(&h).unwrap();
    let store = h.store();
    let base_head = store.head("hot.txt").unwrap().unwrap().id;
    drop(store);

    // Batch 1 touches hot.txt; batch 2 touches hot.txt + new.txt. They
    // overlap on hot.txt, so exactly one may publish.
    let batch1 = proposal("tx-b1", vec![update("hot.txt", &base_head, "from-b1")]);
    let batch2 = proposal(
        "tx-b2",
        vec![
            update("hot.txt", &base_head, "from-b2"),
            first_write("new.txt", "fresh"),
        ],
    );

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for p in [batch1, batch2] {
        let db = h.db.clone();
        let store_root = h.store_root.clone();
        let workspace = h.workspace.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            let mut store = ArtifactRevisionStore::open(&db, &store_root).unwrap();
            let mut engine = TransactionEngine::new(&mut store, &workspace);
            barrier.wait();
            engine.commit(&p)
        }));
    }
    let mut ok = Vec::new();
    let mut conflicts = 0usize;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(manifest) => ok.push(manifest.transaction_id),
            Err(TransformError::MergeConflict { .. }) => conflicts += 1,
            Err(other) => panic!("expected a merge conflict for the loser, got {other}"),
        }
    }
    assert_eq!(ok.len(), 1, "exactly one batch may publish");
    assert_eq!(conflicts, 1);

    // Durable state: only the winner's manifest exists; the loser — even with
    // its exclusive file — published nothing at all.
    let winner = ok[0].clone();
    let loser = if winner == "tx-b1" { "tx-b2" } else { "tx-b1" };
    assert_eq!(h.transaction_rows(&["tx-b1", "tx-b2"]), 1);
    let expected_journal_rows = if winner == "tx-b1" { 1 } else { 2 };
    assert_eq!(h.journal_rows(&winner), expected_journal_rows);
    assert_eq!(h.journal_rows(loser), 0);

    let store = h.store();
    // hot.txt: seed + exactly one winner revision; the loser left no trace.
    let hot_history = store.revisions_for("hot.txt").unwrap();
    assert_eq!(hot_history.len(), 2);
    assert_eq!(
        store.head("hot.txt").unwrap().unwrap().id,
        hot_history[1].id
    );
    if winner == "tx-b2" {
        assert_eq!(store.revisions_for("new.txt").unwrap().len(), 1);
        assert_eq!(h.read_workspace("new.txt"), None, "not materialized yet");
    } else {
        assert!(store.head("new.txt").unwrap().is_none());
        assert!(store.revisions_for("new.txt").unwrap().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

#[test]
fn crash_after_commit_before_first_file_is_recovered_on_restart() {
    let h = harness();
    commit(
        &h,
        &proposal(
            "tx-crash",
            vec![first_write("a.txt", "one"), first_write("sub/b.txt", "two")],
        ),
    );
    // Simulated crash: the process dies before materialize_pending runs.
    drop(h.store());

    // Fresh open = restart. Recovery replays from committed revision bytes.
    let summary = materialize(&h).unwrap();
    assert_eq!(summary.applied, 2);
    assert_eq!(summary.completed_transactions, vec!["tx-crash".to_string()]);
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"one");
    assert_eq!(h.read_workspace("sub/b.txt").unwrap(), b"two");

    let manifest = manifest_of(&h, "tx-crash");
    assert_eq!(manifest.state, TransactionState::Materialized);

    // No revisions were duplicated by the restart.
    let store = h.store();
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.revisions_for("sub/b.txt").unwrap().len(), 1);
}

#[test]
fn crash_halfway_through_materialization_completes_without_duplicates() {
    let h = harness();
    commit(
        &h,
        &proposal(
            "tx-half",
            vec![
                first_write("f1.txt", "first"),
                first_write("blocked.txt", "second"),
                first_write("f3.txt", "third"),
            ],
        ),
    );

    // Inject a failure at an explicit boundary: a directory occupies the
    // second target, so entry 1 commits to disk and entry 2 conflicts.
    std::fs::create_dir_all(h.workspace.join("blocked.txt")).unwrap();
    let err = materialize(&h).unwrap_err();
    assert!(
        matches!(err, TransformError::MaterializationConflict { .. }),
        "expected a conflict at blocked.txt, got {err}"
    );

    // First file applied and journaled; the rest are still pending.
    assert_eq!(h.read_workspace("f1.txt").unwrap(), b"first");
    assert_eq!(h.journal_status("tx-half", 0), "materialized");
    assert_eq!(h.journal_status("tx-half", 1), "pending");
    assert_eq!(h.journal_status("tx-half", 2), "pending");
    assert_eq!(
        manifest_of(&h, "tx-half").state,
        TransactionState::Committed
    );

    // "Restart" after fixing the target: recovery completes the remainder.
    std::fs::remove_dir(h.workspace.join("blocked.txt")).unwrap();
    let summary = materialize(&h).unwrap();
    assert_eq!(
        summary.applied, 2,
        "entries 2 and 3, not a re-run of entry 1"
    );
    assert_eq!(h.read_workspace("blocked.txt").unwrap(), b"second");
    assert_eq!(h.read_workspace("f3.txt").unwrap(), b"third");
    assert_eq!(
        manifest_of(&h, "tx-half").state,
        TransactionState::Materialized
    );

    // Recovery neither corrupted nor duplicated anything.
    let store = h.store();
    for path in ["f1.txt", "blocked.txt", "f3.txt"] {
        assert_eq!(store.revisions_for(path).unwrap().len(), 1);
        assert_eq!(
            store
                .read_content(store.head(path).unwrap().unwrap().id.as_str())
                .unwrap(),
            h.read_workspace(path).unwrap()
        );
    }
}

#[test]
fn target_changed_externally_is_detected_and_not_overwritten() {
    let h = harness();
    commit(&h, &proposal("tx-base", vec![first_write("a.txt", "v1")]));
    materialize(&h).unwrap();
    let store = h.store();
    let base = store.head("a.txt").unwrap().unwrap().id;
    drop(store);

    commit(&h, &proposal("tx-next", vec![update("a.txt", &base, "v2")]));

    // Someone edits the file between commit and materialize.
    std::fs::write(h.workspace.join("a.txt"), b"external edit").unwrap();

    let err = materialize(&h).unwrap_err();
    assert!(matches!(
        err,
        TransformError::MaterializationConflict { .. }
    ));

    // Defined conflict policy: the external bytes survive, the batch stays
    // committed with its journal pending, and metadata is untouched.
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"external edit");
    assert_eq!(h.journal_status("tx-next", 0), "pending");
    assert_eq!(
        manifest_of(&h, "tx-next").state,
        TransactionState::Committed
    );
    let store = h.store();
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 2);

    // Reconcile (restore the expected previous revision), then recover.
    std::fs::write(h.workspace.join("a.txt"), b"v1").unwrap();
    let summary = materialize(&h).unwrap();
    assert_eq!(summary.applied, 1);
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"v2");
    assert_eq!(
        manifest_of(&h, "tx-next").state,
        TransactionState::Materialized
    );
}

#[test]
fn first_write_never_silently_overwrites_an_untracked_file() {
    let h = harness();
    std::fs::write(h.workspace.join("pre.txt"), b"precious untracked data").unwrap();

    // The store has no head, so the metadata commit succeeds...
    commit(
        &h,
        &proposal("tx-pre", vec![first_write("pre.txt", "replacement")]),
    );
    // ...but materialization refuses to destroy unknown bytes.
    let err = materialize(&h).unwrap_err();
    assert!(matches!(
        err,
        TransformError::MaterializationConflict { .. }
    ));
    assert_eq!(
        h.read_workspace("pre.txt").unwrap(),
        b"precious untracked data"
    );
    assert_eq!(h.journal_status("tx-pre", 0), "pending");
    let store = h.store();
    assert_eq!(store.revisions_for("pre.txt").unwrap().len(), 1);
}

#[test]
fn lost_journal_completion_write_is_safe_to_retry() {
    let h = harness();
    commit(&h, &proposal("tx-jr", vec![first_write("a.txt", "alpha")]));
    materialize(&h).unwrap();

    // Inject a failure at an explicit boundary: the file was renamed into
    // place but the journal completion UPDATE was lost (crash in between).
    {
        let conn = rusqlite::Connection::open(&h.db).unwrap();
        conn.execute(
            "UPDATE materialization_journal SET status = 'pending'
             WHERE transaction_id = 'tx-jr' AND ordinal = 0",
            [],
        )
        .unwrap();
    }

    let store = h.store();
    let head_before = store.head("a.txt").unwrap().unwrap().id;
    drop(store);

    // Recovery recognizes the file already holds its committed bytes: no
    // rewrite, no duplicate revision, no head movement.
    let summary = materialize(&h).unwrap();
    assert_eq!(summary.applied, 0);
    assert_eq!(summary.already_current, 1);
    assert_eq!(summary.completed_transactions, vec!["tx-jr".to_string()]);

    assert_eq!(h.journal_status("tx-jr", 0), "materialized");
    assert_eq!(h.read_workspace("a.txt").unwrap(), b"alpha");
    assert_eq!(
        manifest_of(&h, "tx-jr").state,
        TransactionState::Materialized
    );
    let store = h.store();
    assert_eq!(store.revisions_for("a.txt").unwrap().len(), 1);
    assert_eq!(store.head("a.txt").unwrap().unwrap().id, head_before);
}
