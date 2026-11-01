use anyhow::{Context, Result};
use kernel::events::EventBus;
use kernel::identity::{ActorAuthenticator, ActorClaim, ActorKind};
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::AuthorizationPolicy;
use kernel::permissions::types::Capability;
use kernel::recovery::{
    EvidenceSpec, ReconcileOutcome, ReconciliationRequest, RecoveryEngine as KernelRecoveryEngine,
};
use kernel::tasks::checkpoint::CheckpointStore;
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use crate::identity::LocalProcessAuthenticator;

pub const EVENT_TASK_RECONCILED: &str = "TaskReconciledAfterInterruption";

/// Startup reconciliation for the CLI runtime.
///
/// The CLI only *classifies* interrupted invocations.  It deliberately does not
/// re-authorize or resume them: a `RetryReady` step still requires a fresh
/// grant from a policy-bearing runtime (`RecoveryEngine::prepare_retry`), and
/// an `OutcomeUnknown` step requires physical reconciliation first
/// (`RecoveryEngine::reconcile`).  Both are operator decisions, not startup
/// automation.
pub struct RecoveryEngine<'a> {
    task_store: &'a TaskStore,
    event_bus: &'a EventBus,
    checkpoint_store: CheckpointStore,
    checkpoint_recovery: KernelRecoveryEngine,
}

impl<'a> RecoveryEngine<'a> {
    pub fn new(
        task_store: &'a TaskStore,
        event_bus: &'a EventBus,
        db_path: impl AsRef<Path>,
        grant_issuer: GrantIssuer,
        policy: Arc<AuthorizationPolicy>,
    ) -> Result<Self> {
        let db_path = db_path.as_ref();
        let checkpoint_store =
            CheckpointStore::open(db_path).context("Failed to initialize the checkpoint ledger")?;
        let checkpoint_recovery = KernelRecoveryEngine::open(
            db_path,
            task_store.clone(),
            event_bus.clone(),
            grant_issuer,
            policy,
            Arc::new(LocalProcessAuthenticator::new()),
        )
        .context("Failed to initialize kernel checkpoint recovery")?
        .with_probes(tools::reconciler::default_probes());

        Ok(Self {
            task_store,
            event_bus,
            checkpoint_store,
            checkpoint_recovery,
        })
    }

    /// Classifies checkpointed invocations, then fails running tasks that have
    /// no retry-ready checkpoint to resume.
    pub fn reconcile_orphaned_tasks(&self) -> Result<Vec<Uuid>> {
        let recovery_records = self
            .checkpoint_recovery
            .recover_all()
            .context("Failed to recover interrupted invocations")?;
        let retry_ready_tasks: HashSet<_> = self
            .checkpoint_store
            .list_retry_ready()
            .context("Failed to read retry-ready checkpoints")?
            .into_iter()
            .map(|checkpoint| checkpoint.task_id)
            .collect();
        let mut reconciled: HashSet<_> = recovery_records
            .into_iter()
            .map(|record| record.task_id)
            .collect();

        for task in self
            .task_store
            .list_tasks()
            .context("Failed to list tasks during recovery")?
        {
            if task.state != TaskState::Running || retry_ready_tasks.contains(&task.task_id) {
                continue;
            }

            let mut connection = self
                .checkpoint_store
                .connection()
                .context("Failed to open a recovery transaction")?;
            let transaction = connection
                .transaction()
                .context("Failed to begin a recovery transaction")?;
            self.task_store
                .transition_state_with_connection(
                    &transaction,
                    task.task_id,
                    TaskState::Running,
                    TaskState::Failed,
                )
                .with_context(|| format!("Failed to reconcile task {}", task.task_id))?;
            self.event_bus
                .emit_event_with_connection(
                    &transaction,
                    Some(&task.task_id.to_string()),
                    EVENT_TASK_RECONCILED,
                    json!({
                        "task_id": task.task_id,
                        "previous_state": "Running",
                        "new_state": "Failed",
                        "reason": "Interrupted task has no checkpoint approved for retry"
                    }),
                )
                .with_context(|| {
                    format!(
                        "Failed to emit reconciliation event for task {}",
                        task.task_id
                    )
                })?;
            transaction
                .commit()
                .with_context(|| format!("Failed to commit recovery for task {}", task.task_id))?;
            reconciled.insert(task.task_id);
        }

        let mut reconciled: Vec<_> = reconciled.into_iter().collect();
        reconciled.sort_unstable();
        Ok(reconciled)
    }
}

// ── `sky recovery reconcile` ─────────────────────────────────────────────────

/// Operator request to resolve one uncertain invocation.
pub struct ReconcileArgs {
    pub task_id: Uuid,
    pub step_number: usize,
    pub invocation_id: Uuid,
    /// Observation specification as JSON. Never a verdict.
    pub evidence: String,
    pub reason: String,
    /// Optional claimed identity; must agree with the OS process identity.
    pub actor: Option<String>,
}

/// Evidence JSON is an *observation specification*, never a conclusion.
///
/// Accepted shapes:
/// ```json
/// {"kind":"git_commit","repo_root":"/repo","baseline_commit":"abc","intent_message":"msg"}
/// {"kind":"file_checksum","path":"/tmp/x","expected_sha256":"…"}
/// ```
/// `baseline_commit` may be omitted, in which case the runtime uses the baseline
/// it recorded before dispatch — the caller cannot invent one.
fn parse_evidence_spec(raw: &str) -> Result<EvidenceSpec> {
    let value: serde_json::Value =
        serde_json::from_str(raw).context("--evidence must be a JSON object")?;
    let kind = value
        .get("kind")
        .and_then(|kind| kind.as_str())
        .context("--evidence must contain a \"kind\" string")?;

    let required_str = |field: &str| -> Result<String> {
        value
            .get(field)
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .with_context(|| format!("--evidence requires \"{field}\" for kind {kind}"))
    };

    match kind {
        "git_commit" | "git" => {
            let baseline = value
                .get("baseline_commit")
                .and_then(|value| value.as_str())
                .map(str::to_owned);

            Ok(EvidenceSpec::GitCommitAfterBaseline {
                repo_root: PathBuf::from(required_str("repo_root")?),
                // Empty means "use the runtime's recorded baseline".
                baseline_commit: baseline.unwrap_or_default(),
                intent_message: required_str("intent_message")?,
            })
        }
        "file_checksum" | "file" => Ok(EvidenceSpec::FileChecksum {
            path: PathBuf::from(required_str("path")?),
            expected_sha256: required_str("expected_sha256")?,
        }),
        other => anyhow::bail!(
            "unknown evidence kind '{other}': expected 'git_commit' or 'file_checksum'"
        ),
    }
}

/// Resolve an uncertain invocation from independently collected evidence.
///
/// The operator supplies *what to observe*; the runtime authenticates the
/// actor, authorizes the capability, runs the probe, derives the verdict, and
/// writes the reconciliation record plus its audit event.
pub fn reconcile_invocation(db_path: &Path, args: ReconcileArgs) -> Result<()> {
    let task_store = TaskStore::open(db_path).context("Failed to open the task ledger")?;
    let event_bus = EventBus::open(db_path).context("Failed to open the event ledger")?;
    let grant_issuer = GrantIssuer::new();
    let policy = Arc::new(AuthorizationPolicy::new("sky-cli-default", 1));

    // Authenticate first: the grant must name the *verified* actor, and the
    // engine will authenticate the same claim again before acting.
    let authenticator = LocalProcessAuthenticator::new();
    let claim = match &args.actor {
        Some(claimed) => ActorClaim::operator(claimed.clone()),
        None => ActorClaim::process(ActorKind::Operator),
    };
    let verified = authenticator
        .verify(&claim)
        .context("actor authentication failed")?;

    let grant = grant_issuer.issue_grant(
        verified.id.clone(),
        args.task_id,
        vec![Capability::SystemReconciliation {
            task_id: args.task_id,
        }],
        Some(chrono::Duration::minutes(5)),
    );

    let engine = KernelRecoveryEngine::open(
        db_path,
        task_store,
        event_bus,
        grant_issuer,
        policy,
        Arc::new(authenticator),
    )
    .context("Failed to initialize kernel recovery")?
    .with_probes(tools::reconciler::default_probes());

    let mut spec = parse_evidence_spec(&args.evidence)?;
    if let EvidenceSpec::GitCommitAfterBaseline {
        baseline_commit, ..
    } = &mut spec
    {
        if baseline_commit.is_empty() {
            *baseline_commit = engine
                .recorded_baseline(args.task_id, args.step_number)
                .context("Failed to read the recorded baseline")?
                .context(
                    "no pre-dispatch baseline was recorded for this step; \
                     supply \"baseline_commit\" explicitly only if you are certain",
                )?;
        }
    }

    let request = ReconciliationRequest::new(
        args.task_id,
        args.step_number,
        args.invocation_id,
        &args.reason,
        spec,
    );

    let outcome = engine
        .reconcile(&claim, &grant, &request)
        .context("Reconciliation refused")?;

    let record = engine
        .reconciliation_store()
        .list_for_task(args.task_id)
        .context("Failed to read the reconciliation ledger")?
        .into_iter()
        .next_back();

    println!("Reconciliation recorded.");
    println!("  Actor:   {} ({})", verified.id, verified.method.as_str());
    println!(
        "  Outcome: {}",
        match outcome {
            ReconcileOutcome::MarkedSucceeded => "checkpoint Succeeded",
            ReconcileOutcome::RetryAuthorized =>
                "checkpoint RetryReady (retry still needs authorization)",
            ReconcileOutcome::RemainsUnknown { .. } => "remains OutcomeUnknown",
        }
    );
    if let Some(record) = record {
        println!("  Verdict: {} ({})", record.verdict, record.evidence_kind);
        println!("  Source:  {}", record.evidence_source);
    }

    Ok(())
}
