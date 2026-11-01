use sha2::Digest as _;
use skyos_transform::{ArtifactRevisionStore, TransformError};
use std::path::PathBuf;
use tempfile::TempDir;

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

#[test]
fn first_write_head_is_absent_until_first_append() {
    let h = harness();
    let mut store = h.store();

    // Absent head must be observable as absent before any commit.
    assert!(store.head("src/main.rs").unwrap().is_none());
    assert!(store.head_revision_id("src/main.rs").unwrap().is_none());

    let r1 = store
        .append("src/main.rs", b"fn main() {}\n", "task-1", "agent-a")
        .unwrap();

    let head = store.head("src/main.rs").unwrap().unwrap();
    assert_eq!(head.id, r1.id);
    assert!(head.parent_id.is_none());
}

#[test]
fn stored_bytes_reproduce_their_sha256() {
    let h = harness();
    let mut store = h.store();

    let content = b"artifact revision payload\n";
    let r1 = store
        .append("docs/spec.md", content, "task-2", "agent-a")
        .unwrap();

    let expected = format!("{:x}", sha2::Sha256::digest(content));
    assert_eq!(r1.checksum, expected);
    assert_eq!(r1.checksum, ArtifactRevisionStore::checksum_of(content));

    let read_back = store.read_content(r1.id.as_str()).unwrap();
    assert_eq!(read_back, content);
    // Reading must re-verify: recomputed hash of stored bytes matches.
    assert_eq!(ArtifactRevisionStore::checksum_of(&read_back), r1.checksum);
    assert_eq!(r1.size_bytes, content.len() as u64);
}

#[test]
fn appends_chain_parent_revisions_into_a_dag() {
    let h = harness();
    let mut store = h.store();

    let r1 = store
        .append("src/lib.rs", b"v1", "task-3", "agent-a")
        .unwrap();
    let r2 = store
        .append("src/lib.rs", b"v2", "task-3", "agent-b")
        .unwrap();
    let r3 = store
        .append("src/lib.rs", b"v3", "task-4", "agent-a")
        .unwrap();

    assert_eq!(r2.parent_id, Some(r1.id.clone()));
    assert_eq!(r3.parent_id, Some(r2.id.clone()));
    assert_eq!(store.head("src/lib.rs").unwrap().unwrap().id, r3.id);

    let history = store.revisions_for("src/lib.rs").unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].id, r1.id);
    assert_eq!(history[2].id, r3.id);
}

#[test]
fn identical_content_shares_one_blob_but_keeps_distinct_revisions() {
    let h = harness();
    let mut store = h.store();

    let content = b"same bytes, different artifacts";
    let a = store.append("a.txt", content, "task-5", "agent-a").unwrap();
    let b = store.append("b.txt", content, "task-5", "agent-a").unwrap();

    assert_ne!(a.id, b.id);
    assert_eq!(a.checksum, b.checksum);
    // One shared blob on disk.
    assert_eq!(store.blob_path(&a.checksum), store.blob_path(&b.checksum));
    assert!(store.blob_path(&a.checksum).exists());
    // Both revisions read back correctly from the shared blob.
    assert_eq!(store.read_content(a.id.as_str()).unwrap(), content);
    assert_eq!(store.read_content(b.id.as_str()).unwrap(), content);
}

#[test]
fn corrupted_blob_is_detected_on_read() {
    let h = harness();
    let mut store = h.store();

    let r1 = store
        .append("config.toml", b"original", "task-6", "agent-a")
        .unwrap();

    // Corrupt the CAS blob directly (simulates disk tampering/corruption).
    std::fs::write(store.blob_path(&r1.checksum), b"tampered!").unwrap();

    match store.read_content(r1.id.as_str()) {
        Err(TransformError::ChecksumMismatch {
            expected,
            calculated,
            ..
        }) => {
            assert_eq!(expected, r1.checksum);
            assert_ne!(calculated, r1.checksum);
        }
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

#[test]
fn missing_blob_reports_not_found_not_wrong_bytes() {
    let h = harness();
    let mut store = h.store();

    let r1 = store
        .append("gone.bin", b"temporary", "task-7", "agent-a")
        .unwrap();
    std::fs::remove_file(store.blob_path(&r1.checksum)).unwrap();

    match store.read_content(r1.id.as_str()) {
        Err(TransformError::BlobMissing(checksum)) => assert_eq!(checksum, r1.checksum),
        other => panic!("expected BlobMissing, got {other:?}"),
    }
}

#[test]
fn unknown_revision_lookup_fails_cleanly() {
    let h = harness();
    let store = h.store();

    let bogus = skyos_transform::RevisionId::new();
    match store.get_revision(bogus.as_str()) {
        Err(TransformError::RevisionNotFound(id)) => assert_eq!(id, bogus.to_string()),
        other => panic!("expected RevisionNotFound, got {other:?}"),
    }
    // Invalid id strings are rejected by the typed id boundary.
    assert!(matches!(
        "not-a-uuid".parse::<skyos_transform::RevisionId>(),
        Err(TransformError::InvalidRevisionId(_))
    ));
}

#[test]
fn separate_store_instances_share_durable_state() {
    let h = harness();
    let mut writer = h.store();
    let r1 = writer
        .append("shared.txt", b"persisted", "task-8", "agent-a")
        .unwrap();
    drop(writer);

    // A fresh handle (new process-equivalent) observes the same head.
    let reader = h.store();
    let head = reader.head("shared.txt").unwrap().unwrap();
    assert_eq!(head.id, r1.id);
    assert_eq!(reader.read_content(r1.id.as_str()).unwrap(), b"persisted");
}

#[test]
fn concurrent_appends_never_corrupt_revision_metadata() {
    use std::sync::mpsc;
    use std::thread;

    let h = harness();
    // Seed the artifact so all threads chain from an existing head.
    let mut seed = h.store();
    seed.append("hot.txt", b"base", "task-9", "agent-seed")
        .unwrap();
    drop(seed);

    let threads = 4usize;
    let per_thread = 3usize;
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::new();
    for t in 0..threads {
        let db = h.db.clone();
        let store_root = h.store_root.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let mut store = ArtifactRevisionStore::open(&db, &store_root).unwrap();
            for i in 0..per_thread {
                let content = format!("thread-{t}-rev-{i}");
                let revision = store
                    .append(
                        "hot.txt",
                        content.as_bytes(),
                        "task-9",
                        &format!("agent-{t}"),
                    )
                    .expect("concurrent append must succeed at the metadata layer");
                tx.send(revision.id.to_string()).unwrap();
            }
        }));
    }
    drop(tx);
    for handle in handles {
        handle.join().unwrap();
    }
    let published: Vec<String> = rx.iter().collect();
    assert_eq!(published.len(), threads * per_thread);

    let store = h.store();
    let history = store.revisions_for("hot.txt").unwrap();
    // Seed + every concurrent append persisted; none lost or duplicated.
    assert_eq!(history.len(), 1 + threads * per_thread);
    // Exactly one head, and it references a revision that exists in history.
    let head = store.head("hot.txt").unwrap().expect("head must exist");
    assert!(history.iter().any(|r| r.id == head.id));
    // Every revision's parent resolves (no dangling references).
    for revision in &history {
        if let Some(parent) = &revision.parent_id {
            assert!(store.get_revision(parent.as_str()).is_ok());
        }
        // Content remains readable and hash-verified.
        assert!(store.read_content(revision.id.as_str()).is_ok());
    }
}
