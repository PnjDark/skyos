/// Phase 6.0 acceptance — `sky recovery reconcile`.
///
/// Exercises the operator path end to end: a real database with a real
/// `OutcomeUnknown` checkpoint, a real Git repository whose commit the probe
/// must discover, and a durable reconciliation record plus audit event.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::AuthorizationPolicy;
use kernel::recovery::{ReconciliationStore, RecoveryEngine};
use kernel::tasks::checkpoint::{
    compute_argument_fingerprint, compute_idempotency_key, CheckpointInvocation, CheckpointStatus,
    CheckpointStore, SideEffectSemantics,
};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use sky_cli::identity::LocalProcessAuthenticator;
use sky_cli::recovery::{reconcile_invocation, ReconcileArgs};
use uuid::Uuid;

use kernel::identity::ActorAuthenticator;

const INTENT: &str = "phase6: governed reconciliation acceptance";
const STEP: usize = 0;

struct Fixture {
    _dir: tempfile::TempDir,
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
    /// A dispatched-then-uncertain checkpoint over a real repository.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("runtime_state.db");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        git(&repo, &["init"]);
        git(&repo, &["config", "user.name", "Phase 6 Test"]);
        git(&repo, &["config", "user.email", "phase6@sky.invalid"]);
        std::fs::write(repo.join("seed.txt"), "seed\n").unwrap();
        git(&repo, &["add", "--", "seed.txt"]);
        git(&repo, &["commit", "-m", "baseline"]);
        let baseline = git(&repo, &["rev-parse", "HEAD"]);

        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        let checkpoint_store = CheckpointStore::open(&db_path).unwrap();

        let task_id = task_store
            .create_task("reconcile acceptance", TaskState::Ready, 0)
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
            "recovery-agent",
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
        // The runtime records the pre-dispatch baseline; the reconciler is
        // bounded by it.
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

        // Simulate the crash classification: dispatched, outcome unknown.
        let connection = checkpoint_store.connection().unwrap();
        CheckpointStore::mark_outcome_unknown(&connection, task_id, STEP).unwrap();
        drop(connection);

        Self {
            _dir: dir,
            db_path,
            repo,
            task_id,
            invocation_id,
            baseline,
        }
    }

    fn evidence_json(&self) -> String {
        serde_json::json!({
            "kind": "git_commit",
            "repo_root": self.repo,
            "intent_message": INTENT,
        })
        .to_string()
    }

    fn status(&self) -> CheckpointStatus {
        CheckpointStore::open(&self.db_path)
            .unwrap()
            .latest_for_task(self.task_id)
            .unwrap()
            .unwrap()
            .status
    }
}

#[test]
fn reconcile_command_records_a_durable_decision_from_a_real_probe() {
    let fixture = Fixture::new();

    // The effect really happened: a commit with the recorded intent exists.
    std::fs::write(fixture.repo.join("work.txt"), "payload\n").unwrap();
    git(&fixture.repo, &["add", "--", "work.txt"]);
    git(&fixture.repo, &["commit", "-m", INTENT]);

    reconcile_invocation(
        &fixture.db_path,
        ReconcileArgs {
            task_id: fixture.task_id,
            step_number: STEP,
            invocation_id: fixture.invocation_id,
            evidence: fixture.evidence_json(),
            reason: "commit verified in the repository".into(),
            actor: None,
        },
    )
    .expect("reconciliation must succeed");

    assert_eq!(fixture.status(), CheckpointStatus::Succeeded);

    let store = ReconciliationStore::open(&fixture.db_path).unwrap();
    let records = store.list_for_task(fixture.task_id).unwrap();
    assert_eq!(records.len(), 1, "exactly one durable decision");
    let record = &records[0];
    assert_eq!(record.verdict, "ConfirmedSucceeded");
    assert_eq!(record.evidence_kind, "GitCommit");
    assert_eq!(record.actor_kind, "Operator");
    assert_eq!(
        record.auth_method, "LocalProcess",
        "the host authenticator must report verified process identity"
    );
    assert_eq!(record.invocation_id, Some(fixture.invocation_id));
    assert!(record.grant_id.is_some(), "the authority must be recorded");
    assert!(
        record.evidence.contains(&fixture.baseline),
        "the observation must be bounded by the recorded baseline: {}",
        record.evidence
    );

    let events = EventBus::open(&fixture.db_path)
        .unwrap()
        .get_events_for_task(&fixture.task_id.to_string())
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "InvocationReconciled"),
        "the decision must be in the audit ledger"
    );
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "PermissionGranted"),
        "the capability check must be audited"
    );
}

#[test]
fn reconcile_command_refuses_a_wrong_invocation_id() {
    let fixture = Fixture::new();
    std::fs::write(fixture.repo.join("work.txt"), "payload\n").unwrap();
    git(&fixture.repo, &["add", "--", "work.txt"]);
    git(&fixture.repo, &["commit", "-m", INTENT]);

    let error = reconcile_invocation(
        &fixture.db_path,
        ReconcileArgs {
            task_id: fixture.task_id,
            step_number: STEP,
            invocation_id: Uuid::new_v4(),
            evidence: fixture.evidence_json(),
            reason: "mistyped invocation".into(),
            actor: None,
        },
    )
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(
        message.contains("does not match the invocation"),
        "unexpected error: {message}"
    );
    assert_eq!(
        fixture.status(),
        CheckpointStatus::OutcomeUnknown,
        "a mismatched invocation must change nothing"
    );
    assert!(ReconciliationStore::open(&fixture.db_path)
        .unwrap()
        .list_for_task(fixture.task_id)
        .unwrap()
        .is_empty());
}

#[test]
fn reconcile_command_rejects_a_verdict_shaped_evidence_argument() {
    let fixture = Fixture::new();

    let error = reconcile_invocation(
        &fixture.db_path,
        ReconcileArgs {
            task_id: fixture.task_id,
            step_number: STEP,
            invocation_id: fixture.invocation_id,
            // The Phase 5 API would have accepted this. It must not any more.
            evidence: serde_json::json!({ "outcome": "ConfirmedSucceeded" }).to_string(),
            reason: "asserting success".into(),
            actor: None,
        },
    )
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(
        message.contains("kind"),
        "a verdict-shaped argument must be rejected as an invalid spec: {message}"
    );
    assert_eq!(fixture.status(), CheckpointStatus::OutcomeUnknown);
}

#[test]
fn reconcile_command_refuses_when_the_effect_is_absent_and_says_so() {
    let fixture = Fixture::new();

    // No commit with the recorded intent exists.
    reconcile_invocation(
        &fixture.db_path,
        ReconcileArgs {
            task_id: fixture.task_id,
            step_number: STEP,
            invocation_id: fixture.invocation_id,
            evidence: fixture.evidence_json(),
            reason: "no commit found".into(),
            actor: None,
        },
    )
    .expect("reconciliation itself succeeds; the verdict is 'not executed'");

    assert_eq!(
        fixture.status(),
        CheckpointStatus::RetryReady,
        "proven absence authorizes a retry, but only a retry"
    );

    let record = ReconciliationStore::open(&fixture.db_path)
        .unwrap()
        .list_for_task(fixture.task_id)
        .unwrap()
        .remove(0);
    assert_eq!(record.verdict, "ConfirmedNotExecuted");
    assert_eq!(
        record.action,
        kernel::recovery::ReconciliationAction::AuthorizeRetry
    );
}

/// The engine must still be reachable programmatically with a denial, proving
/// the CLI is not bypassing the capability gate.
#[test]
fn the_engine_denies_a_grant_scoped_to_another_task() {
    let fixture = Fixture::new();
    let other_task = Uuid::new_v4();

    let grant_issuer = GrantIssuer::new();
    let verified = LocalProcessAuthenticator::new()
        .verify(&kernel::identity::ActorClaim::process(
            kernel::identity::ActorKind::Operator,
        ))
        .unwrap();
    let grant = grant_issuer.issue_grant(
        verified.id.clone(),
        other_task,
        vec![
            kernel::permissions::types::Capability::SystemReconciliation {
                task_id: other_task,
            },
        ],
        None,
    );

    let engine = RecoveryEngine::open(
        &fixture.db_path,
        TaskStore::open(&fixture.db_path).unwrap(),
        EventBus::open(&fixture.db_path).unwrap(),
        grant_issuer,
        Arc::new(AuthorizationPolicy::new("test", 1)),
        Arc::new(LocalProcessAuthenticator::new()),
    )
    .unwrap()
    .with_probes(tools::reconciler::default_probes());

    let request = kernel::recovery::ReconciliationRequest::new(
        fixture.task_id,
        STEP,
        fixture.invocation_id,
        "wrong scope",
        kernel::recovery::EvidenceSpec::GitCommitAfterBaseline {
            repo_root: fixture.repo.clone(),
            baseline_commit: fixture.baseline.clone(),
            intent_message: INTENT.into(),
        },
    );

    let error = engine
        .reconcile(
            &kernel::identity::ActorClaim::process(kernel::identity::ActorKind::Operator),
            &grant,
            &request,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        kernel::recovery::RecoveryError::AuthorizationDenied { .. }
    ));
}
