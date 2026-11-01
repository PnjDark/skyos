//! Phase 5.3 crash-injection worker.
//!
//! This binary is deliberately *not* part of the runtime.  It exists to drive
//! the real execution boundary — persist `Pending`, persist `Dispatched`,
//! perform a real Git commit, persist the outcome — inside a real OS process
//! writing to a real SQLite WAL database, and then die at a selected boundary.
//!
//! A parent process re-opens the same database from a *fresh* process and runs
//! recovery.  Nothing here mocks success: the commit hash in the report is a
//! commit that exists on disk.
//!
//! Subcommands
//! ───────────
//! `run`        execute the boundary and crash there
//! `recover`    classify unresolved checkpoints (no authorization, no dispatch)
//! `authorize`  classify, then attempt re-authorization for retry-ready steps
//! `resume`     re-dispatch a step that recovery authorized (or blindly, with
//!              `--blind`, to demonstrate that the guard is what prevents a
//!              duplicate side effect)
//! `reconcile`  apply physical evidence to an outcome-unknown step
//!
//! Exit codes for `run`
//! ────────────────────
//! 70 after Pending, before Dispatched
//! 71 after Dispatched, before the tool invocation
//! 72 after the physical side effect, before the result is persisted
//! 73 after the result is persisted, before task completion
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::identity::{
    ActorAuthenticator, ActorClaim, ActorKind, AuthError, AuthMethod, VerifiedIdentity,
};
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::policy::{AuthorizationPolicy, policy_for_agent};
use kernel::permissions::types::{Capability, CapabilityGrant};
use kernel::recovery::{
    AuthorizationContext, AuthorizationStore, EvidenceSpec, ReconcileOutcome,
    ReconciliationRequest, ReconciliationStore, RecoveryEngine, RecoveryServices,
};
use kernel::tasks::checkpoint::{
    CheckpointInvocation, CheckpointStore, SideEffectSemantics, compute_argument_fingerprint,
    compute_idempotency_key,
};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use serde_json::json;
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolOutput, ToolStatus};
use uuid::Uuid;

const AGENT: &str = "crash-agent";
const OPERATOR: &str = "crash-harness-operator";
const TOOL: &str = "git";
const OPERATION: &str = "commit";
const COMMIT_MESSAGE: &str = "crash-harness: durable side effect";

/// Test composition only: the harness authenticates the operator without a
/// platform trust anchor, and says so in the recorded method.
struct HarnessAuthenticator;

impl ActorAuthenticator for HarnessAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        if claim.kind == ActorKind::Agent {
            return Err(AuthError::UnsupportedActorKind {
                kind: ActorKind::Agent,
                reason: "the harness never authenticates an agent for reconciliation".into(),
            });
        }
        Ok(VerifiedIdentity::new(
            OPERATOR,
            ActorKind::Operator,
            AuthMethod::HarnessOnly,
        ))
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────────

struct Args {
    command: String,
    db: PathBuf,
    repo: PathBuf,
    boundary: String,
    crash: String,
    report: Option<PathBuf>,
    policy: String,
    evidence: String,
    reason: String,
    baseline: Option<String>,
    blind: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut command = None;
        let mut db = None;
        let mut repo = None;
        let mut boundary = "none".to_string();
        let mut crash = "exit".to_string();
        let mut report = None;
        let mut policy = "allow".to_string();
        let mut evidence = "discover".to_string();
        let mut reason = "reviewed the interrupted invocation".to_string();
        let mut baseline = None;
        let mut blind = false;

        let mut raw = std::env::args().skip(1);
        while let Some(arg) = raw.next() {
            match arg.as_str() {
                "--db" => db = Some(PathBuf::from(next(&mut raw, "--db")?)),
                "--repo" => repo = Some(PathBuf::from(next(&mut raw, "--repo")?)),
                "--boundary" => boundary = next(&mut raw, "--boundary")?,
                "--crash" => crash = next(&mut raw, "--crash")?,
                "--report" => report = Some(PathBuf::from(next(&mut raw, "--report")?)),
                "--policy" => policy = next(&mut raw, "--policy")?,
                "--evidence" => evidence = next(&mut raw, "--evidence")?,
                "--reason" => reason = next(&mut raw, "--reason")?,
                "--baseline" => baseline = Some(next(&mut raw, "--baseline")?),
                "--blind" => blind = true,
                other if command.is_none() => command = Some(other.to_string()),
                other => bail!("unexpected argument: {other}"),
            }
        }

        Ok(Self {
            command: command
                .context("missing subcommand (run|recover|authorize|resume|reconcile)")?,
            db: db.context("--db is required")?,
            repo: repo.context("--repo is required")?,
            boundary,
            crash,
            report,
            policy,
            evidence,
            reason,
            baseline,
            blind,
        })
    }
}

fn next(raw: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    raw.next()
        .with_context(|| format!("{flag} requires a value"))
}

// ── Runtime bundle ────────────────────────────────────────────────────────────

struct HarnessRuntime {
    repo: PathBuf,
    task_store: TaskStore,
    event_bus: EventBus,
    checkpoint_store: CheckpointStore,
    authorization_store: AuthorizationStore,
    reconciliation_store: ReconciliationStore,
    grant_issuer: GrantIssuer,
    policy: Arc<AuthorizationPolicy>,
    artifact_registry: ArtifactRegistry,
}

fn build_policy(kind: &str, repo: &Path) -> AuthorizationPolicy {
    match kind {
        // An offline policy change that no longer permits writes at all.
        "deny" => AuthorizationPolicy::new("crash-harness-policy", 2),
        _ => policy_for_agent(
            "crash-harness-policy",
            1,
            AGENT,
            [
                Capability::GitWrite {
                    repo_root: repo.to_path_buf(),
                },
                Capability::GitRead {
                    repo_root: repo.to_path_buf(),
                },
            ],
        ),
    }
}

impl HarnessRuntime {
    fn open(args: &Args) -> Result<Self> {
        let db_path = &args.db;
        let task_store = TaskStore::open(db_path)?;
        let event_bus = EventBus::open(db_path)?;
        let checkpoint_store = CheckpointStore::open(db_path)?;
        let authorization_store = AuthorizationStore::open(db_path)?;
        let reconciliation_store = ReconciliationStore::open(db_path)?;
        let cas = db_path
            .parent()
            .context("database path has no parent")?
            .join("cas");
        let artifact_registry = ArtifactRegistry::open(db_path, cas)?;
        let policy = Arc::new(build_policy(&args.policy, &args.repo));

        Ok(Self {
            repo: args.repo.clone(),
            task_store,
            event_bus,
            checkpoint_store,
            authorization_store,
            reconciliation_store,
            grant_issuer: GrantIssuer::new(),
            policy,
            artifact_registry,
        })
    }

    fn recovery_engine(&self) -> RecoveryEngine {
        RecoveryEngine::new(RecoveryServices {
            checkpoint_store: self.checkpoint_store.clone(),
            task_store: self.task_store.clone(),
            event_bus: self.event_bus.clone(),
            grant_issuer: self.grant_issuer.clone(),
            authorization_store: self.authorization_store.clone(),
            reconciliation_store: self.reconciliation_store.clone(),
            policy: self.policy.clone(),
            authenticator: Arc::new(HarnessAuthenticator),
            probes: tools::reconciler::default_probes(),
        })
    }

    /// Mint the reconciliation authority for one task, held by the operator.
    fn reconciliation_grant(&self, task_id: Uuid) -> CapabilityGrant {
        self.grant_issuer.issue_grant(
            OPERATOR,
            task_id,
            vec![Capability::SystemReconciliation { task_id }],
            Some(chrono::Duration::minutes(15)),
        )
    }

    fn git_capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::GitWrite {
                repo_root: self.repo.clone(),
            },
            Capability::GitRead {
                repo_root: self.repo.clone(),
            },
        ]
    }

    fn issuance_grant(&self, task_id: Uuid) -> CapabilityGrant {
        self.grant_issuer.issue_grant(
            AGENT,
            task_id,
            self.git_capabilities(),
            Some(chrono::Duration::hours(1)),
        )
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("crash-worker: {error:#}");
            std::process::exit(2);
        }
    };

    let result = match args.command.as_str() {
        "run" => run_worker(&args).await,
        "recover" => recover(&args),
        "authorize" => authorize(&args),
        "resume" => resume(&args).await,
        "reconcile" => reconcile(&args),
        "requeue" => requeue(&args),
        "inspect" => inspect(&args),
        other => Err(anyhow::anyhow!("unknown subcommand: {other}")),
    };

    if let Err(error) = result {
        eprintln!("crash-worker: {error:#}");
        std::process::exit(1);
    }
}

// ── run: the real execution boundary ─────────────────────────────────────────

async fn run_worker(args: &Args) -> Result<()> {
    let mut runtime = HarnessRuntime::open(args)?;

    let task_id = runtime
        .task_store
        .create_task("crash-harness", TaskState::Ready, 1)?;
    runtime
        .task_store
        .transition_state(task_id, TaskState::Ready, TaskState::Claimed)?;
    runtime
        .task_store
        .transition_state(task_id, TaskState::Claimed, TaskState::Running)?;

    let grant = runtime.issuance_grant(task_id);
    let arguments = json!({ "message": COMMIT_MESSAGE });
    let idempotency_key = compute_idempotency_key(&task_id, 0, TOOL, OPERATION, &arguments);
    let argument_fingerprint = compute_argument_fingerprint(&arguments);
    let invocation_id = Uuid::new_v4();

    // What did the world look like immediately before the attempt?  This is the
    // baseline a later reconciliation probe compares against, and it is written
    // by the runtime, not by the agent.
    let baseline_head = probe_head(&runtime.repo)?;

    // 1. Persist Pending + the capability intent, in one transaction.
    {
        let mut connection = runtime.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;
        CheckpointStore::write_pending_invocation(
            &transaction,
            task_id,
            AGENT,
            0,
            &CheckpointInvocation {
                invocation_id,
                idempotency_key: idempotency_key.clone(),
                argument_fingerprint: argument_fingerprint.clone(),
                semantics: SideEffectSemantics::Reconcilable,
                tool_id: TOOL.into(),
                operation_id: OPERATION.into(),
            },
        )?;
        AuthorizationStore::record_with_connection(
            &transaction,
            &AuthorizationContext {
                task_id,
                step_number: 0,
                agent_id: AGENT.into(),
                capabilities: grant.capabilities.clone(),
                required_capability: UnifiedToolRegistry::required_capability_kind(TOOL, OPERATION),
                policy_id: runtime.policy.policy_id().to_string(),
                policy_version: runtime.policy.version(),
                recorded_at: Utc::now().to_rfc3339(),
            },
        )?;
        runtime.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            "ToolInvocationPending",
            json!({
                "invocation_id": invocation_id,
                "idempotency_key": &idempotency_key,
                "argument_fingerprint": &argument_fingerprint,
                "step_number": 0,
                "tool_id": TOOL,
                "operation_id": OPERATION,
                "baseline_head": &baseline_head,
            }),
        )?;
        transaction.commit()?;
    }
    if args.boundary == "pending" {
        report(args, &runtime, task_id, None)?;
        crash(args, 70);
    }

    // 2. Persist Dispatched.
    {
        let mut connection = runtime.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;
        CheckpointStore::mark_dispatched(
            &transaction,
            task_id,
            0,
            invocation_id,
            &idempotency_key,
            TOOL,
            OPERATION,
        )?;
        runtime.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            "ToolInvocationDispatched",
            json!({
                "invocation_id": invocation_id,
                "idempotency_key": &idempotency_key,
                "step_number": 0,
                "baseline_head": &baseline_head,
            }),
        )?;
        transaction.commit()?;
    }
    if args.boundary == "dispatched" {
        report(args, &runtime, task_id, None)?;
        crash(args, 71);
    }

    // 3. The physical side effect — a real commit in a real repository.
    let commit_hash = {
        let mut registry = UnifiedToolRegistry::new(
            &runtime.event_bus,
            &mut runtime.artifact_registry,
            &runtime.grant_issuer,
        );
        let context = ToolContext::with_invocation_id(task_id, AGENT, invocation_id);
        let result = registry
            .dispatch(
                &context,
                &grant,
                InvocationRequest {
                    tool_id: TOOL.into(),
                    operation_id: OPERATION.into(),
                    parameters: arguments.clone(),
                    idempotency_key: Some(idempotency_key.clone()),
                },
                &runtime.repo,
            )
            .await;

        if result.status != ToolStatus::Succeeded {
            bail!(
                "git commit failed before the crash boundary: {:?}",
                result.error_message
            );
        }

        match &result.output {
            ToolOutput::Text(text) => text.trim().to_string(),
            other => bail!("unexpected commit output: {other:?}"),
        }
    };

    if args.boundary == "after-effect" {
        report(args, &runtime, task_id, Some(commit_hash))?;
        crash(args, 72);
    }

    // 4. Persist the observed outcome.
    {
        let mut connection = runtime.checkpoint_store.connection()?;
        let transaction = connection.transaction()?;
        CheckpointStore::mark_succeeded(&transaction, task_id, 0)?;
        runtime.event_bus.emit_event_with_connection(
            &transaction,
            Some(&task_id.to_string()),
            "AgentStepCompleted",
            json!({
                "step_number": 0,
                "correlation_id": invocation_id,
                "status": "Succeeded",
                "commit_hash": commit_hash,
            }),
        )?;
        transaction.commit()?;
    }
    if args.boundary == "after-result" {
        report(args, &runtime, task_id, Some(commit_hash))?;
        crash(args, 73);
    }

    // 5. Task completion.
    runtime
        .task_store
        .transition_state(task_id, TaskState::Running, TaskState::Completed)?;
    report(args, &runtime, task_id, Some(commit_hash))
}

// ── recover / authorize / resume / reconcile ─────────────────────────────────

fn recover(args: &Args) -> Result<()> {
    let runtime = HarnessRuntime::open(args)?;
    let engine = runtime.recovery_engine();
    let records = engine.recover_all()?;

    let decisions: Vec<_> = records
        .iter()
        .map(|record| {
            json!({
                "task_id": record.task_id,
                "step_number": record.step_number,
                "prior_status": record.prior_status.as_str(),
                "decision": format!("{:?}", record.decision),
            })
        })
        .collect();

    let mut obligations = Vec::new();
    for task in runtime.task_store.list_tasks()? {
        let pending = engine.obligations(task.task_id)?;
        obligations.push(json!({
            "task_id": task.task_id,
            "state": task.state.to_string(),
            "retry_ready_steps": pending.retry_ready.iter().map(|c| c.step_number).collect::<Vec<_>>(),
            "outcome_unknown_steps": pending.outcome_unknown.iter().map(|c| c.step_number).collect::<Vec<_>>(),
        }));
    }

    emit_report(
        args,
        &json!({
            "command": "recover",
            "recovered": records.len(),
            "decisions": decisions,
            "obligations": obligations,
        }),
    )
}

fn authorize(args: &Args) -> Result<()> {
    let runtime = HarnessRuntime::open(args)?;
    let engine = runtime.recovery_engine();
    engine.recover_all()?;

    let mut attempts = Vec::new();
    for task in runtime.task_store.list_tasks()? {
        let obligations = engine.obligations(task.task_id)?;
        for checkpoint in obligations.retry_ready {
            let entry = match engine.prepare_retry(task.task_id, checkpoint.step_number, AGENT) {
                Ok(permit) => json!({
                    "task_id": task.task_id,
                    "step_number": checkpoint.step_number,
                    "result": "granted",
                    "grant_id": permit.grant.grant_id,
                    "capabilities": permit.grant.capabilities,
                    "policy_id": permit.policy_id,
                    "policy_version": permit.policy_version,
                }),
                Err(error) => json!({
                    "task_id": task.task_id,
                    "step_number": checkpoint.step_number,
                    "result": "refused",
                    "error": error.to_string(),
                }),
            };
            attempts.push(entry);
        }
    }

    let decisions = runtime.authorization_store.list_decisions(
        runtime
            .task_store
            .list_tasks()?
            .first()
            .map(|task| task.task_id)
            .unwrap_or_else(Uuid::nil),
    )?;

    emit_report(
        args,
        &json!({
            "command": "authorize",
            "attempts": attempts,
            "recorded_decisions": decisions.len(),
        }),
    )
}

async fn resume(args: &Args) -> Result<()> {
    let mut runtime = HarnessRuntime::open(args)?;

    // --blind deliberately bypasses the recovery authorization gate.  It is the
    // control experiment: it shows that a duplicate side effect *is* physically
    // possible, so the guard's refusal is what prevents it.
    if args.blind {
        let mut dispatched = 0usize;
        for task in runtime.task_store.list_tasks()? {
            let Some(checkpoint) = runtime.checkpoint_store.latest_for_task(task.task_id)? else {
                continue;
            };
            let Some(idempotency_key) = checkpoint.idempotency_key.clone() else {
                continue;
            };
            let invocation_id = checkpoint.invocation_id.unwrap_or_else(Uuid::new_v4);
            let grant = runtime.issuance_grant(task.task_id);

            let mut registry = UnifiedToolRegistry::new(
                &runtime.event_bus,
                &mut runtime.artifact_registry,
                &runtime.grant_issuer,
            );
            let context = ToolContext::with_invocation_id(task.task_id, AGENT, invocation_id);
            let result = registry
                .dispatch(
                    &context,
                    &grant,
                    InvocationRequest {
                        tool_id: TOOL.into(),
                        operation_id: OPERATION.into(),
                        parameters: json!({ "message": COMMIT_MESSAGE }),
                        idempotency_key: Some(idempotency_key),
                    },
                    &runtime.repo,
                )
                .await;
            runtime.event_bus.emit_event(
                Some(&task.task_id.to_string()),
                "BlindRetryDispatched",
                json!({
                    "step_number": checkpoint.step_number,
                    "prior_status": checkpoint.status.as_str(),
                    "status": format!("{:?}", result.status),
                }),
            )?;
            if result.status == ToolStatus::Succeeded {
                dispatched += 1;
            }
        }
        return emit_report(
            args,
            &json!({ "command": "resume", "blind": true, "dispatched": dispatched }),
        );
    }

    let engine = runtime.recovery_engine();
    let mut dispatched = 0usize;
    let mut refused: Vec<String> = Vec::new();

    for task in runtime.task_store.list_tasks()? {
        let obligations = engine.obligations(task.task_id)?;

        for checkpoint in &obligations.retry_ready {
            let step_number = checkpoint.step_number;

            let (grant, idempotency_key, invocation_id) =
                match engine.prepare_retry(task.task_id, step_number, AGENT) {
                    Ok(permit) => (permit.grant, permit.idempotency_key, permit.invocation_id),
                    Err(error) => {
                        refused.push(error.to_string());
                        continue;
                    }
                };

            {
                let mut connection = runtime.checkpoint_store.connection()?;
                let transaction = connection.transaction()?;
                CheckpointStore::mark_dispatched(
                    &transaction,
                    task.task_id,
                    step_number,
                    invocation_id,
                    &idempotency_key,
                    TOOL,
                    OPERATION,
                )?;
                runtime.event_bus.emit_event_with_connection(
                    &transaction,
                    Some(&task.task_id.to_string()),
                    "ToolInvocationReDispatched",
                    json!({
                        "invocation_id": invocation_id,
                        "idempotency_key": &idempotency_key,
                        "step_number": step_number,
                    }),
                )?;
                transaction.commit()?;
            }

            let arguments = json!({ "message": COMMIT_MESSAGE });
            let mut registry = UnifiedToolRegistry::new(
                &runtime.event_bus,
                &mut runtime.artifact_registry,
                &runtime.grant_issuer,
            );
            let context = ToolContext::with_invocation_id(task.task_id, AGENT, invocation_id);
            let result = registry
                .dispatch(
                    &context,
                    &grant,
                    InvocationRequest {
                        tool_id: TOOL.into(),
                        operation_id: OPERATION.into(),
                        parameters: arguments,
                        idempotency_key: Some(idempotency_key.clone()),
                    },
                    &runtime.repo,
                )
                .await;

            let mut connection = runtime.checkpoint_store.connection()?;
            let transaction = connection.transaction()?;
            if result.status == ToolStatus::Succeeded {
                CheckpointStore::mark_succeeded(&transaction, task.task_id, step_number)?;
                dispatched += 1;
            } else {
                CheckpointStore::mark_outcome_unknown(&transaction, task.task_id, step_number)?;
            }
            runtime.event_bus.emit_event_with_connection(
                &transaction,
                Some(&task.task_id.to_string()),
                "RetryCompleted",
                json!({
                    "step_number": step_number,
                    "status": format!("{:?}", result.status),
                    "error": result.error_message,
                }),
            )?;
            transaction.commit()?;

            // The fresh grant authorized exactly this retry.
            let _ = runtime.grant_issuer.revoke_grant(&grant.grant_id);
        }
    }

    emit_report(
        args,
        &json!({
            "command": "resume",
            "blind": false,
            "dispatched": dispatched,
            "refused": refused,
        }),
    )
}

fn reconcile(args: &Args) -> Result<()> {
    let runtime = HarnessRuntime::open(args)?;
    let engine = runtime.recovery_engine();
    let claim = ActorClaim::process(ActorKind::Operator);

    let mut verdicts = Vec::new();
    for task in runtime.task_store.list_tasks()? {
        let obligations = engine.obligations(task.task_id)?;
        for checkpoint in obligations.outcome_unknown {
            // The caller names the observation; the engine runs the probe and
            // derives the verdict. `--baseline` exists so the adversarial test
            // can prove an unrecorded baseline is refused.
            let baseline = match &args.baseline {
                Some(requested) => requested.clone(),
                None => recorded_baseline(&runtime, task.task_id, checkpoint.step_number)?
                    .context("no recorded pre-dispatch baseline; refusing to reconcile")?,
            };

            let spec = EvidenceSpec::GitCommitAfterBaseline {
                repo_root: runtime.repo.clone(),
                baseline_commit: baseline,
                intent_message: COMMIT_MESSAGE.to_string(),
            };
            let request = ReconciliationRequest::new(
                task.task_id,
                checkpoint.step_number,
                checkpoint
                    .invocation_id
                    .context("checkpoint has no recorded invocation id")?,
                &args.reason,
                spec,
            );
            let grant = runtime.reconciliation_grant(task.task_id);

            match engine.reconcile(&claim, &grant, &request) {
                Ok(outcome) => {
                    let record = runtime
                        .reconciliation_store
                        .list_for_task(task.task_id)?
                        .into_iter()
                        .next_back();
                    verdicts.push(json!({
                        "task_id": task.task_id,
                        "step_number": checkpoint.step_number,
                        "verdict": match outcome {
                            ReconcileOutcome::MarkedSucceeded => "MarkedSucceeded",
                            ReconcileOutcome::RetryAuthorized => "RetryAuthorized",
                            ReconcileOutcome::RemainsUnknown { .. } => "RemainsUnknown",
                        },
                        "evidence": record.as_ref().map(|r| r.evidence.as_str()).unwrap_or_default(),
                        "evidence_kind": record.as_ref().map(|r| r.evidence_kind.as_str()).unwrap_or_default(),
                        "actor_kind": record.as_ref().map(|r| r.actor_kind.as_str()).unwrap_or_default(),
                        "auth_method": record.as_ref().map(|r| r.auth_method.as_str()).unwrap_or_default(),
                    }));
                }
                Err(error) => verdicts.push(json!({
                    "task_id": task.task_id,
                    "step_number": checkpoint.step_number,
                    "error": error.to_string(),
                })),
            }
        }
    }

    emit_report(
        args,
        &json!({
            "command": "reconcile",
            "evidence": args.evidence,
            "reason": args.reason,
            "verdicts": verdicts,
        }),
    )
}

/// The baseline HEAD the runtime recorded immediately before dispatch.
///
/// Phase 6.0 reads it from the ledger event; the engine independently checks
/// that the request's baseline matches it.
fn recorded_baseline(
    runtime: &HarnessRuntime,
    task_id: Uuid,
    step_number: usize,
) -> Result<Option<String>> {
    let events = runtime
        .event_bus
        .get_events_for_task(&task_id.to_string())?;

    Ok(events
        .iter()
        .filter(|event| event.event_type == "ToolInvocationDispatched")
        .filter(|event| {
            event
                .payload
                .get("step_number")
                .and_then(|value| value.as_u64())
                .map(|step| step as usize)
                == Some(step_number)
        })
        .filter_map(|event| {
            event
                .payload
                .get("baseline_head")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .next_back())
}

/// Operator action: move a `Blocked` task back to the queue (`Blocked -> Ready`).
///
/// Reconciliation proves what happened, but it does not re-run anything.  A
/// blocked task must be re-queued before the runtime will authorize work for
/// it again; this is the explicit judgement call that separates "the world is
/// understood" from "start working on it again".  The kernel refuses the action
/// while any step is still `OutcomeUnknown`, and records who asked for it.
fn requeue(args: &Args) -> Result<()> {
    let runtime = HarnessRuntime::open(args)?;
    let engine = runtime.recovery_engine();
    let claim = ActorClaim::process(ActorKind::Operator);
    let mut requeued = Vec::new();
    let mut refused = Vec::new();

    for task in runtime.task_store.list_tasks()? {
        if task.state != TaskState::Blocked {
            continue;
        }
        let grant = runtime.reconciliation_grant(task.task_id);
        match engine.requeue(&claim, &grant, task.task_id, &args.reason) {
            Ok(()) => requeued.push(task.task_id),
            Err(error) => refused.push(json!({
                "task_id": task.task_id,
                "error": error.to_string(),
            })),
        }
    }

    emit_report(
        args,
        &json!({
            "command": "requeue",
            "reason": args.reason,
            "requeued": requeued,
            "refused": refused,
        }),
    )
}

fn inspect(args: &Args) -> Result<()> {
    let runtime = HarnessRuntime::open(args)?;
    let mut tasks = Vec::new();
    for task in runtime.task_store.list_tasks()? {
        let checkpoint = runtime.checkpoint_store.latest_for_task(task.task_id)?;
        let reconciliations: Vec<_> = runtime
            .reconciliation_store
            .list_for_task(task.task_id)?
            .into_iter()
            .map(|record| {
                json!({
                    "action": record.action.as_str(),
                    "actor_id": record.actor_id,
                    "reason": record.reason,
                    "evidence": record.evidence,
                    "prior_status": record.prior_status,
                    "new_status": record.new_status,
                })
            })
            .collect();
        tasks.push(json!({
            "task_id": task.task_id,
            "state": task.state.to_string(),
            "checkpoint_status": checkpoint.as_ref().map(|c| c.status.as_str()),
            "step_number": checkpoint.as_ref().map(|c| c.step_number),
            "invocation_id": checkpoint.as_ref().and_then(|c| c.invocation_id),
            "idempotency_key": checkpoint.as_ref().and_then(|c| c.idempotency_key.clone()),
            "reconciliations": reconciliations,
        }));
    }

    emit_report(
        args,
        &json!({
            "command": "inspect",
            "tasks": tasks,
        }),
    )
}

// ── Reporting and crash mechanics ────────────────────────────────────────────

/// Read the repository HEAD directly, out of band.
fn probe_head(repo: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .context("failed to read the repository HEAD")?;

    if !output.status.success() {
        bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn report(
    args: &Args,
    runtime: &HarnessRuntime,
    task_id: Uuid,
    commit_hash: Option<String>,
) -> Result<()> {
    let checkpoint = runtime
        .checkpoint_store
        .latest_for_task(task_id)?
        .context("no checkpoint persisted")?;
    let task_state = runtime
        .task_store
        .get_task(&task_id)?
        .map(|task| task.state.to_string())
        .unwrap_or_else(|| "missing".to_string());

    emit_report(
        args,
        &json!({
            "command": "run",
            "task_id": task_id,
            "boundary": args.boundary,
            "checkpoint_status": checkpoint.status.as_str(),
            "task_state": task_state,
            "commit_hash": commit_hash,
            "invocation_id": checkpoint.invocation_id,
            "idempotency_key": checkpoint.idempotency_key,
        }),
    )
}

fn emit_report(args: &Args, payload: &serde_json::Value) -> Result<()> {
    let rendered = serde_json::to_string_pretty(payload)?;
    if let Some(path) = &args.report {
        std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("failed to write report {}", path.display()))?;
    }
    println!("{rendered}");
    Ok(())
}

/// Terminate exactly at the selected boundary.
fn crash(args: &Args, code: i32) -> ! {
    match args.crash.as_str() {
        // SIGKILL-equivalent: no destructors, no flush, no unwinding.
        "abort" => std::process::abort(),
        // Let the parent terminate this process while it sits at the boundary.
        "wait" => {
            let marker = args
                .report
                .clone()
                .unwrap_or_else(|| PathBuf::from("crash-report.json"))
                .with_extension("ready");
            std::fs::write(&marker, b"ready")
                .unwrap_or_else(|error| panic!("failed to write kill marker: {error}"));
            println!("READY-FOR-KILL");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_secs(120));
            std::process::exit(code)
        }
        _ => std::process::exit(code),
    }
}
