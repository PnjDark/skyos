/// Phase 6.0 CLI acceptance gate — against the compiled `sky` executable.
///
/// Every test here spawns a real `sky` process with an isolated `HOME`, so the
/// child opens its own runtime database at `<home>/.sky/runtime_state.db`. The
/// parent builds that database, performs a real Git commit, marks the
/// invocation `OutcomeUnknown`, and then lets a *fresh process* authenticate
/// through `LocalProcessAuthenticator`, run the probe, and write the decision.
///
/// Nothing is mocked: the actor identity asserted here is the operating
/// system's SID/uid as seen by the child process.
use std::path::{Path, PathBuf};
use std::process::Command;

use kernel::events::EventBus;
use kernel::recovery::{ReconciliationAction, ReconciliationStore};
use kernel::tasks::checkpoint::{
    compute_argument_fingerprint, compute_idempotency_key, CheckpointInvocation, CheckpointStatus,
    CheckpointStore, SideEffectSemantics,
};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use uuid::Uuid;

const INTENT: &str = "phase6: cli process acceptance";
const STEP: usize = 0;
const SKY: &str = env!("CARGO_BIN_EXE_sky");

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    repo: PathBuf,
    task_id: Uuid,
    invocation_id: Uuid,
    baseline: String,
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git required for this test");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

impl Fixture {
    /// A real task, a real dispatched invocation, and a real commit that landed
    /// before the worker "died".
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let runtime_dir = home.join(".sky");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let db_path = runtime_dir.join("runtime_state.db");

        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init"]);
        git(&repo, &["config", "user.name", "Phase 6 CLI Test"]);
        git(&repo, &["config", "user.email", "phase6-cli@sky.invalid"]);
        std::fs::write(repo.join("seed.txt"), "seed\n").unwrap();
        git(&repo, &["add", "--", "seed.txt"]);
        git(&repo, &["commit", "-m", "baseline"]);
        let baseline = git(&repo, &["rev-parse", "HEAD"]);

        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        let checkpoint_store = CheckpointStore::open(&db_path).unwrap();

        // A task that a previous run left Blocked, as crash recovery would.
        let task_id = task_store
            .create_task("cli reconcile acceptance", TaskState::Ready, 0)
            .unwrap();
        task_store
            .transition_state(task_id, TaskState::Ready, TaskState::Claimed)
            .unwrap();
        task_store
            .transition_state(task_id, TaskState::Claimed, TaskState::Running)
            .unwrap();

        let invocation_id = Uuid::new_v4();
        let arguments = serde_json::json!({ "message": INTENT });
        let key = compute_idempotency_key(&task_id, STEP, "git", "commit", &arguments);
        let fingerprint = compute_argument_fingerprint(&arguments);

        let mut connection = checkpoint_store.connection().unwrap();
        let transaction = connection.transaction().unwrap();
        CheckpointStore::write_pending_invocation(
            &transaction,
            task_id,
            "cli-test-agent",
            STEP,
            &CheckpointInvocation {
                invocation_id,
                idempotency_key: key.clone(),
                argument_fingerprint: fingerprint,
                semantics: SideEffectSemantics::Reconcilable,
                tool_id: "git".into(),
                operation_id: "commit".into(),
            },
        )
        .unwrap();
        CheckpointStore::mark_dispatched(
            &transaction,
            task_id,
            STEP,
            invocation_id,
            &key,
            "git",
            "commit",
        )
        .unwrap();
        event_bus
            .emit_event_with_connection(
                &transaction,
                Some(&task_id.to_string()),
                "ToolInvocationDispatched",
                serde_json::json!({
                    "step_number": STEP,
                    "invocation_id": invocation_id,
                    "baseline_head": baseline,
                }),
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);

        // The external effect really happens…
        std::fs::write(repo.join("work.txt"), "payload\n").unwrap();
        git(&repo, &["add", "--", "work.txt"]);
        git(&repo, &["commit", "-m", INTENT]);

        // …and the worker dies before recording it.
        let connection = checkpoint_store.connection().unwrap();
        CheckpointStore::mark_outcome_unknown(&connection, task_id, STEP).unwrap();
        drop(connection);
        task_store
            .transition_state(task_id, TaskState::Running, TaskState::Blocked)
            .unwrap();

        Self {
            _dir: dir,
            home,
            db_path,
            repo,
            task_id,
            invocation_id,
            baseline,
        }
    }

    fn evidence(&self) -> String {
        serde_json::json!({
            "kind": "git_commit",
            "repo_root": self.repo,
            "intent_message": INTENT,
        })
        .to_string()
    }

    /// Run the compiled CLI as a separate process against the isolated home.
    fn sky(&self, args: &[&str]) -> std::process::Output {
        Command::new(SKY)
            .args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .current_dir(&self.repo)
            .output()
            .expect("the sky binary must launch")
    }

    fn reconcile(
        &self,
        task_id: Uuid,
        step: usize,
        invocation_id: Uuid,
        evidence: &str,
    ) -> std::process::Output {
        self.sky(&[
            "recovery",
            "reconcile",
            &task_id.to_string(),
            &step.to_string(),
            "--invocation-id",
            &invocation_id.to_string(),
            "--evidence",
            evidence,
        ])
    }

    fn status(&self) -> CheckpointStatus {
        CheckpointStore::open(&self.db_path)
            .unwrap()
            .latest_for_task(self.task_id)
            .unwrap()
            .unwrap()
            .status
    }

    fn records(&self) -> Vec<kernel::recovery::ReconciliationRecord> {
        ReconciliationStore::open(&self.db_path)
            .unwrap()
            .list_for_task(self.task_id)
            .unwrap()
    }
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ── Happy path across a real process boundary ───────────────────────────────

#[test]
fn a_fresh_cli_process_reconciles_a_governed_invocation() {
    let fixture = Fixture::new();

    let output = fixture.reconcile(
        fixture.task_id,
        STEP,
        fixture.invocation_id,
        &fixture.evidence(),
    );
    assert!(
        output.status.success(),
        "the CLI must succeed: {}",
        stderr(&output)
    );

    // Reopen from the parent: this is the durability check across processes.
    assert_eq!(fixture.status(), CheckpointStatus::Succeeded);

    let records = fixture.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.verdict, "ConfirmedSucceeded");
    assert_eq!(record.evidence_kind, "GitCommit");
    assert_eq!(record.action, ReconciliationAction::AdoptExistingArtifact);
    assert_eq!(record.invocation_id, Some(fixture.invocation_id));
    assert_eq!(record.actor_kind, "Operator");
    assert_eq!(
        record.auth_method, "LocalProcess",
        "a real process token must be used, not an environment claim"
    );
    assert!(
        record.actor_id.starts_with("win-sid:") || record.actor_id.starts_with("unix-uid:"),
        "the recorded actor must be the OS identity, got {}",
        record.actor_id
    );
    assert!(record.grant_id.is_some());
    assert!(
        record.evidence.contains(&fixture.baseline),
        "the observation must be bounded by the recorded baseline: {}",
        record.evidence
    );

    let events = EventBus::open(&fixture.db_path)
        .unwrap()
        .get_events_for_task(&fixture.task_id.to_string())
        .unwrap();
    for expected in ["InvocationReconciled", "PermissionGranted"] {
        assert!(
            events.iter().any(|event| event.event_type == expected),
            "missing audit event {expected}"
        );
    }
}

#[test]
fn the_reconciled_state_survives_a_second_restart() {
    let fixture = Fixture::new();
    let output = fixture.reconcile(
        fixture.task_id,
        STEP,
        fixture.invocation_id,
        &fixture.evidence(),
    );
    assert!(output.status.success(), "{}", stderr(&output));

    // Two independent reopens, each constructing fresh runtime objects.
    for _ in 0..2 {
        let store = CheckpointStore::open(&fixture.db_path).unwrap();
        assert_eq!(
            store
                .latest_for_task(fixture.task_id)
                .unwrap()
                .unwrap()
                .status,
            CheckpointStatus::Succeeded
        );
        let records = ReconciliationStore::open(&fixture.db_path)
            .unwrap()
            .list_for_task(fixture.task_id)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].verdict, "ConfirmedSucceeded");
    }
}

// ── Negative matrix ─────────────────────────────────────────────────────────

#[test]
fn a_wrong_invocation_id_is_rejected_before_the_probe_runs() {
    let fixture = Fixture::new();

    let output = fixture.reconcile(fixture.task_id, STEP, Uuid::new_v4(), &fixture.evidence());

    assert!(!output.status.success(), "the CLI must refuse");
    let message = stderr(&output);
    assert!(
        message.contains("does not match the invocation"),
        "the refusal must name the mismatch: {message}"
    );
    assert_eq!(fixture.status(), CheckpointStatus::OutcomeUnknown);
    assert!(fixture.records().is_empty());
}

#[test]
fn a_wrong_step_number_is_rejected() {
    let fixture = Fixture::new();

    let output = fixture.reconcile(
        fixture.task_id,
        7,
        fixture.invocation_id,
        &fixture.evidence(),
    );

    assert!(!output.status.success());
    assert_eq!(fixture.status(), CheckpointStatus::OutcomeUnknown);
    assert!(fixture.records().is_empty());
}

#[test]
fn verdict_shaped_evidence_is_rejected() {
    let fixture = Fixture::new();
    let evidence = serde_json::json!({ "verdict": "ConfirmedSucceeded" }).to_string();

    let output = fixture.reconcile(fixture.task_id, STEP, fixture.invocation_id, &evidence);

    assert!(!output.status.success(), "a verdict is not an observation");
    assert_eq!(fixture.status(), CheckpointStatus::OutcomeUnknown);
    assert!(fixture.records().is_empty());
}

#[test]
fn a_claimed_identity_that_is_not_the_operator_is_refused() {
    let fixture = Fixture::new();

    let args = vec![
        "recovery".to_string(),
        "reconcile".to_string(),
        fixture.task_id.to_string(),
        STEP.to_string(),
        "--invocation-id".to_string(),
        fixture.invocation_id.to_string(),
        "--evidence".to_string(),
        fixture.evidence(),
        "--actor".to_string(),
        "definitely-not-the-os-user".to_string(),
    ];
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = fixture.sky(&borrowed);

    assert!(
        !output.status.success(),
        "identity claims cannot be borrowed"
    );
    assert_eq!(fixture.status(), CheckpointStatus::OutcomeUnknown);
    assert!(fixture.records().is_empty());
}

#[test]
fn an_unavailable_probe_fails_without_fabricating_a_verdict() {
    let fixture = Fixture::new();
    let not_a_repo = fixture._dir.path().join("not-a-repository");
    std::fs::create_dir_all(&not_a_repo).unwrap();
    let evidence = serde_json::json!({
        "kind": "git_commit",
        "repo_root": not_a_repo,
        "intent_message": INTENT,
    })
    .to_string();

    let output = fixture.reconcile(fixture.task_id, STEP, fixture.invocation_id, &evidence);

    assert!(!output.status.success(), "a failed probe must not succeed");
    assert_eq!(
        fixture.status(),
        CheckpointStatus::OutcomeUnknown,
        "a failed observation must leave the checkpoint untouched"
    );
    assert!(
        fixture.records().is_empty(),
        "a failed probe must not write a reconciliation record"
    );
}

#[test]
fn repeating_a_reconciliation_is_refused_and_writes_nothing_extra() {
    let fixture = Fixture::new();

    let first = fixture.reconcile(
        fixture.task_id,
        STEP,
        fixture.invocation_id,
        &fixture.evidence(),
    );
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(fixture.records().len(), 1);

    let second = fixture.reconcile(
        fixture.task_id,
        STEP,
        fixture.invocation_id,
        &fixture.evidence(),
    );
    assert!(
        !second.status.success(),
        "a settled checkpoint is not reconcilable twice"
    );
    assert_eq!(
        fixture.records().len(),
        1,
        "the second attempt must not add a record"
    );
    assert_eq!(fixture.status(), CheckpointStatus::Succeeded);
}
