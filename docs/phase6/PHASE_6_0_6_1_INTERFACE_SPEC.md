# Phase 6.0–6.1 — Interface Specification & Dependency Map

**Status:** proposal for sign-off. No Phase 6 runtime code has been written.
**Basis:** an inventory of the workspace as it stands at Phase 5 lock (commit-less
working tree, 234/234 Windows tests, clippy clean).
**Scope:** 6.0 (governed reconciliation + authenticated identity) and 6.1
(delegation kernel). 6.2–6.5 are out of scope except where they constrain these
two interfaces.

> Note on evidence: the Windows run in `docs/phase5/evidence/` is 234 tests. I
> have no Linux run in this workspace, so I cannot corroborate the 227 figure;
> if it came from your own environment I would like the log filed alongside the
> others so the record has one source of truth.

---

## 1. Inventory — what actually exists

### 1.1 Crate graph (from the manifests, not from intent)

```
kernel            (no workspace deps; rusqlite, uuid, chrono, sha2)
  ├── tools       (kernel)                           15 registered operations
  │     ├── models        (tools)                    ← the model layer sits above tools
  │     │     └── agents  (kernel, tools, models)
  │     └── crash_harness (kernel, tools)            [test harness]
  ├── transform   (kernel)
  ├── provisioner (no workspace deps)                [pure git/fs library]
  └── sky-cli     (kernel, tools, provisioner)       [leaf]
```

Three facts with Phase 6 consequences:

* **`provisioner` does not depend on `kernel`.** The governed wrapper
  (`GovernedProvisioner`, policy checks, ledger events) lives in
  `clients/cli/src/workspace.rs`. A multi-agent runtime cannot call into the CLI
  leaf, so **6.3 must hoist that wrapper into a reusable crate**; the pure
  provisioner is already reusable.
* **`agents` cannot depend on `sky-cli`.** Anything the orchestrator needs from
  the CLI must move down the graph first.
* **`models` depends on `tools`** (for `ToolSchema`). That is already an
  inverted-looking edge; 6.2's budget/usage reporting must live in `models`
  without dragging kernel types further up, or the edge gets worse.

### 1.2 Task and identity models

| Item | Reality | Location |
|---|---|---|
| `Task` | `{task_id, title, state, priority, retry_count, created_at, updated_at}` | `kernel/src/tasks/store.rs` |
| `TaskState` | `Created, Ready, Claimed, Running, Waiting, Blocked, Escalated, Failed, Completed` | `kernel/src/tasks/state.rs` |
| Transitions | hard-coded `can_transition_to` matrix | same |
| `TaskStore` | `open`, `create_task(title, state, priority)`, `get_task`, `transition_state`, `transition_state_with_connection`, `list_tasks`, `database_path` | `kernel/src/tasks/store.rs` |
| Parent/child | **absent** | — |
| Dependencies | **absent** | — |
| Budget on task | **absent** (`AgentBudget` exists in `agents/src/types.rs`, in-memory only) | — |
| Agent assignment | **absent** | — |
| Agent identity | `String` (`GrantIssuer::issue_grant`, `ToolContext.agent_id`); no authentication anywhere | — |
| Actor identity | `String` (`task_reconciliations.actor_id`, caller-supplied) | — |

`Waiting` already means *agent paused mid-execution* (`Running→Waiting→Running`).
It is **not** a dependency state, and Phase 6.1 must not overload it.

### 1.3 Checkpoint, recovery, reconciliation

| Item | Reality | Location |
|---|---|---|
| `TaskCheckpoint` | task, step, invocation, idempotency key, argument fingerprint, semantics, tool/op, status, time | `kernel/src/tasks/checkpoint.rs` |
| `CheckpointStatus` | `Pending, Dispatched, Succeeded, Failed, OutcomeUnknown, RetryReady` | same |
| `RecoveryEngine` | `recover_all`, `reconcile`, `requeue`, `obligations`, `prepare_retry`, `authorizer` | `kernel/src/recovery/mod.rs` |
| `ReconciliationEvidence` | `EffectObserved{evidence:String}`, `EffectAbsent{evidence:String}`, `Indeterminate{reason}` — **caller-supplied** | same |
| `ReconciliationRequest` | `{actor_id: String, reason: String, evidence: ReconciliationEvidence}` | same |
| `task_reconciliations` | `reconciliation_id, task_id, step_number, actor_id, action, reason, evidence, prior_status, new_status, created_at` | migration M6 |
| Authorization context | persisted capabilities + **runtime-derived** `required_capability` + policy id/version | migration M5 + addendum |
| `RetryPermit` | binds step/invocation/key/fingerprint/grant/policy | `kernel/src/recovery/mod.rs` |

**The 6.0 gap in one line:** `reconcile` currently accepts a verdict. The
operator-facing probe that produces it lives in `crash_harness`, and the engine
has no way to tell a probed verdict from an asserted one.

### 1.4 Permissions

| Item | Reality |
|---|---|
| `Capability` | 11 resource-scoped variants (`FileSystemRead/Write`, `ProcessExec`, `NetworkOutbound`, `ContainersExec`, `GitRead/Write`, `ContainerRun`, `HardwareAccess`, `NetworkBind`, `DomainAccess`) |
| `CapabilityKind` | family-only mirror of the above, added in Phase 5.2 |
| Scope subsumption | `PolicyValidator::capability_covers` |
| `PolicyEngine` | `evaluate`, `evaluate_checked`, `authorize_capability_set`; every decision is audited |
| `GrantIssuer` | in-memory `HashMap<Uuid, CapabilityGrant>`; `issue_grant`, `get_grant`, `get_active_grant_for_{task,agent_task}`, `revoke_grant` |
| Authentication | **none** |

Adding `SystemReconciliation` means touching: the enum, `CapabilityKind`,
`PolicyValidator::capability_covers`, the engine's request matcher, and the CLI
flag parser. It does **not** touch `export_schemas`, because reconciliation is a
runtime service rather than a dispatched tool operation (§3.1).

### 1.5 Tool manifest

`ToolSchema { tool_id, operation_id, description, required_capability: String,
parameters_schema }`, produced by `UnifiedToolRegistry::export_schemas()` (15
operations). `required_capability_kind()` maps a schema's string to a
`CapabilityKind`. `side_effect_semantics(tool, op)` declares the retry contract.
Dispatch always re-checks the policy per operation.

### 1.6 Artifacts and transformation

| Item | Reality |
|---|---|
| `Artifact` | `{artifact_id, task_id: Option<String>, artifact_type, hash, size_bytes, location_uri, metadata}` |
| `ArtifactRegistry` | CAS-backed; `register_text_artifact`, `register_file_artifact`, `get_artifact`, `get_artifacts_for_task`, `get_artifact_by_hash`, `get_lineage_chain` |
| `ArtifactType` | `File, Directory, Log, Diff, Binary, Snapshot, SvgVector, LottieAnimation, AudioTrack, RenderedVideo, BrandTokenPatch` |
| Revisions | `ArtifactRevisionStore` — per-artifact OCC DAG, `head`, `append_if_head_matches`, `evaluate_expectation` |
| Transactions | `TransactionEngine::commit` / `materialize_pending`, `TransactionManifest`, journal rows |
| Conflicts | `TransformError::MergeConflict{path, expected, actual, reason}` — already structured |

This is the machinery 6.4 needs. Nothing new is required for typed deliverables
except a *selector* contract (§4.7).

### 1.7 Provisioner

`RepositoryProvisioner::provision_workspace(task_id, project_id, branch,
base_commit)` → `WorkspaceContext { task_id: String, project_id, base_commit,
workspace_kind, canonical_root, created_at }`, plus
`recover_interrupted_provisioning`. Worktrees staged at `.sky/tmp/prov_<task>`,
renamed into `.sky/worktrees/<task>`, lock file `.sky/provision_<task>.lock`.
`GovernedProvisioner::provision(sandbox, request, &grant)` adds the kernel
authorization + events, but lives in `sky-cli`.

### 1.8 Event ledger

`EventBus::emit_event(task_id: Option<&str>, event_type: &str, payload: Value)`,
`emit_event_with_connection` (transactional), `get_events_for_task`. Event types
are free-form string constants scattered across crates. There is no schema or
registry; `task_id` is a single optional FK-shaped column, which matters for a
cascade (events for a child are not visible under the parent's id).

---

## 2. Gap analysis against the Phase 6 proposal

| Proposal (your message) | Reality | Consequence |
|---|---|---|
| `Capability::SystemReconciliation` | does not exist | additive, touches 5 sites (§3.3) |
| `ReconciliationRequest{invocation_id, evidence_descriptor}` | no `invocation_id`, evidence is a verdict not a descriptor | **invert**: request names *what to observe*, engine runs the probe |
| `ReconciliationOutcome{ConfirmedSucceeded, ConfirmedNotExecuted, Indeterminate}` | `ReconcileOutcome{MarkedSucceeded, RetryAuthorized, RemainsUnknown}` conflates *verdict* and *ledger effect* | split into `Verdict` (world) and `Effect` (ledger) |
| `actor_id: String` "authenticated" | unauthenticated string | need an unforgeable `AuthenticatedActor` |
| `DelegatedTask{parentTaskId, dependencies, budget, state}` | none of these columns exist | migration M8 |
| State `Executing` | `Running`/`Claimed` | map, don't add |
| State `Validating` | absent | add (§4.2) |
| State `Cancelled` | absent | add (terminal) |
| `TaskBudget{tokens, steps, seconds}` | absent; `AgentBudget` is in-memory, per-run | persist; token enforcement blocked on provider usage |
| `dependencies: string[]` | absent | join table + transactional gate |
| `tools/src/reconciler.rs` | probe exists only in `crash_harness` | hoist, but see §3.1 on *how* |

---

## 3. Phase 6.0 — Governed reconciliation and authenticated identity

### 3.1 The property to make structurally impossible

> An agent cannot reconcile its own uncertain operation by asserting that it
> succeeded, and no caller can hand the engine a verdict.

Three independent guards, each sufficient on its own:

1. **The engine runs the probe.** `RecoveryEngine::reconcile` accepts an
   `EvidenceSpec` (what to observe), never a verdict. The engine resolves the
   spec against an injected `EvidenceProbe` and derives the verdict itself.
2. **The engine authenticates, the caller cannot mint.** Callers pass an
   `ActorClaim` (a claim + credential); the engine runs the configured
   `ActorAuthenticator` and constructs the `AuthenticatedActor` internally. The
   type has **no public constructor**, so no other crate can produce one — the
   host cannot hand the engine a pre-blessed actor even if it wants to. The
   engine refuses `ActorKind::Agent` unconditionally in 6.0.
3. **The capability is required and resource-scoped.** `SystemReconciliation`
   is checked through the same audited `PolicyEngine` path as every other
   capability.

Deliberate choice: **reconciliation is a runtime service, not a dispatched tool
operation.** If it were registered in `export_schemas`, every agent would see it
in its tool list and could attempt it. It stays outside the dispatcher; agents
have no path to it at all in 6.0.

### 3.2 Authenticated identity (new module `kernel/src/identity/`)

```rust
pub enum ActorKind { Operator, Runtime, Agent }

pub enum AuthMethod {
    LocalProcess { platform_id: String },   // uid / token SID
    SignedToken  { key_id: String },
    HarnessOnly,                            // #[cfg(test)] composition
}

/// What a caller claims. Plain data; carrying no authority on its own.
pub struct ActorClaim {
    pub claimed_id: String,
    pub kind: ActorKind,
    pub credential: Credential,
}

/// What an authenticator returns. Plain data, deliberately forgeable — it never
/// travels across the API boundary; the engine consumes it immediately.
pub struct VerifiedIdentity {
    pub id: String,
    pub kind: ActorKind,
    pub method: AuthMethod,
    pub verified_at: DateTime<Utc>,
}

pub trait ActorAuthenticator: Send + Sync {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError>;
}

/// Authority-bearing. Private fields, no public constructor, no From<String>.
pub struct AuthenticatedActor {
    id: String,
    kind: ActorKind,
    method: AuthMethod,
    authenticated_at: DateTime<Utc>,
}

impl AuthenticatedActor {
    /// Crate-private. Only the engine's authenticated entry points call this.
    pub(crate) fn from_verified(verified: VerifiedIdentity) -> Self;

    pub fn id(&self) -> &str;
    pub fn kind(&self) -> ActorKind;
    pub fn method(&self) -> &AuthMethod;
}
```

Why the split matters: a Rust type with private fields cannot be constructed by
another crate, so an "unforgeable actor" only works if the minting happens
**inside** the crate that defines it. The first draft of this section had the
host minting the actor, which is impossible and would have been caught at
implementation time. The corrected shape puts verification in the engine:

```rust
let verified = self.authenticator.verify(claim)?;   // host decides *who*
let actor = AuthenticatedActor::from_verified(verified); // kernel decides *whether*
if actor.kind() == ActorKind::Agent { return Err(AgentSelfReconciliation); }
```

The host owns the trust anchor (it is the runtime owner and already owns the
database); it does **not** get to bypass attribution or the agent ban.

The kernel stays free of platform dependencies. Candidate authenticators, to be
chosen in Decision 1:

| Implementation | Strength | Cost |
|---|---|---|
| `LocalProcessAuthenticator` (uid / token SID) | real local identity | `libc` / `windows-sys` in the **host** |
| `LedgerOwnerAuthenticator` (OS user owning the runtime DB) | weak but honest | platform metadata calls in the host |
| `StaticOperatorAuthenticator` (configured operator id) | not authentication | zero |

Recommendation: `LocalProcessAuthenticator` in the CLI, `HarnessOnly` in tests.
If Decision 1 lands on `StaticOperatorAuthenticator`, the audit record must say
`method = UnverifiedConfigured`, and this report must not describe it as
authenticated.

### 3.3 Capability and request

```rust
// kernel/src/permissions/types.rs
Capability::SystemReconciliation { ledger: PathBuf }   // scope = the runtime database

ToolInvocationRequest::SystemReconciliation { ledger: PathBuf, action: ReconciliationActionKind }
```

`capability_covers(SystemReconciliation{a}, SystemReconciliation{b})` →
`validate_fs_access(b, a)`, so a grant for one runtime's ledger cannot reconcile
another's. If you prefer unscoped operator authority, say so (Decision 2) — the
scope is what makes the capability consistent with the rest of the model.

### 3.4 Evidence probes (`tools/src/reconciler.rs`)

```rust
pub trait EvidenceProbe: Send + Sync {
    fn kind(&self) -> EvidenceKind;
    fn probe(&self, spec: &EvidenceSpec, ctx: &ProbeContext) -> Result<EvidenceRef, ProbeError>;
}

pub enum EvidenceSpec {
    /// Did a commit matching the recorded intent appear after the baseline?
    GitCommitAfterBaseline { repo_root: PathBuf, baseline_commit: String, intent_message: String },
    /// Does the file currently hold exactly the committed bytes?
    FileChecksum { path: PathBuf, expected_sha256: String },
}

pub struct EvidenceRef {
    pub kind: EvidenceKind,          // GitCommit | FileChecksum
    pub observed: serde_json::Value, // structured: commit hash, range, stdout digest
    pub collected_at: DateTime<Utc>,
    pub source: String,              // "git log --format=%H%x1f%s <baseline>..HEAD"
}
```

`RecoveryEngine` gains `probes: Vec<Arc<dyn EvidenceProbe>>` in
`RecoveryServices`, and resolves the spec by kind. A missing probe is a refusal,
not a default.

`ProbeContext` supplies the recorded invocation identity (task, step, baseline)
so the probe never trusts values the caller invented. The baseline is already
persisted at dispatch time (`ToolInvocationDispatched.baseline_head` in the
harness); in 6.0 it moves into the checkpoint's authorization context so the
runtime owns it rather than an event payload.

### 3.5 Verdict vs effect

```rust
/// What the world shows. Produced only by a probe.
pub enum ReconciliationVerdict {
    ConfirmedSucceeded { evidence: EvidenceRef },
    ConfirmedNotExecuted { evidence: EvidenceRef },
    Indeterminate { reason: String },
}

/// What the ledger does. Derived from the verdict, never chosen by the caller.
pub enum ReconcileOutcome {
    MarkedSucceeded,
    RetryAuthorized,
    RemainsUnknown { reason: String },
}
```

Mapping is fixed: `ConfirmedSucceeded → Succeeded`, `ConfirmedNotExecuted →
RetryReady` (still needs `prepare_retry`), `Indeterminate → unchanged + Blocked`.

### 3.6 Ledger changes (migration M7)

Add to `task_reconciliations`: `invocation_id TEXT`,
`evidence_kind TEXT`, `evidence_source TEXT`, `evidence_json TEXT`,
`auth_method TEXT`, `actor_kind TEXT`. Existing rows get NULLs; the reader
treats NULL provenance as "legacy, not independently verified" and never as
proof.

### 3.7 API surface after 6.0

```rust
impl RecoveryEngine {
    pub fn reconcile(
        &self,
        claim: &ActorClaim,
        request: ReconciliationRequest,   // { task_id, step_number, spec, reason }
    ) -> Result<ReconcileOutcome, RecoveryError>;

    pub fn requeue(
        &self,
        claim: &ActorClaim,
        task_id: Uuid,
        reason: &str,
    ) -> Result<(), RecoveryError>;
}
```

`RecoveryServices` gains `authenticator: Arc<dyn ActorAuthenticator>`.
`ReconciliationRequest` loses `evidence` and `actor_id`; it gains `spec`. This is
a breaking change to the Phase 5 API — intentional, and the reason 6.0 is worth a
package.

### 3.8 Invariants and the tests that will prove them

| # | Invariant | Test |
|---|---|---|
| 1 | An agent actor cannot reconcile | `agent_actor_cannot_reconcile` |
| 2 | A caller cannot supply a verdict | `ReconciliationRequest` has no verdict field; `verified_evidence_cannot_be_constructed_by_callers` |
| 2b | No other crate can mint an actor | `AuthenticatedActor` has no public constructor; a doc-test asserts the import fails to compile |
| 3 | A missing probe refuses | `unknown_evidence_kind_is_refused` |
| 4 | A lying probe cannot be injected | `probe_registry_is_closed_at_construction` |
| 5 | Indeterminate stays blocked | `indeterminate_keeps_task_blocked` (exists, re-expressed) |
| 6 | Reconciliation preserves the checkpoint identity | `reconciliation_preserves_invocation_identity` (exists) |
| 7 | Every decision carries authenticated provenance | `reconciliation_records_actor_and_method` |
| 8 | Capability scope is enforced | `reconciliation_capability_is_ledger_scoped` |

### 3.9 Non-goals for 6.0

No IdP, no remote operators, no signed artifact verification, no new tool
operations, no change to the executor's dispatch path.

---

## 4. Phase 6.1 — Delegation kernel

### 4.1 Structure

A **kernel module**, not a new crate and not a second engine:
`kernel/src/delegation/` owning the parent-child graph, admission control,
budget accounting, cancellation cascade and completion gate. It reads/writes the
existing `tasks` table through `TaskStore`.

### 4.2 State machine changes

| Proposed | Decision | Why |
|---|---|---|
| `Executing` | **map to `Running`** | already exists; no value in renaming |
| `Validating` | **add** | a child finishing is not a child succeeding; needs a durable state between Running and Completed |
| `Cancelled` | **add** (terminal) | needed for cascade |
| `Waiting (dependency)` | **do not add** | `Waiting` already means agent-paused; dependency gating uses `Created → Ready` (§4.4) |

New transitions:

```
(Running, Validating)
(Validating, Completed)     only through the completion gate
(Validating, Failed)
(Validating, Blocked)
(Created | Ready | Claimed | Running | Waiting | Blocked | Validating, Cancelled)
```

`Validating` is entered when the child agent's run terminates, never by the agent
itself; the runtime owns the transition.

### 4.3 Schema (migration M8)

```sql
ALTER TABLE tasks ADD COLUMN parent_task_id      TEXT;
ALTER TABLE tasks ADD COLUMN assigned_agent_id   TEXT;
ALTER TABLE tasks ADD COLUMN objective           TEXT;
ALTER TABLE tasks ADD COLUMN deliverable_contract TEXT;   -- JSON: DeliverableContract
ALTER TABLE tasks ADD COLUMN budget_max_steps     INTEGER;
ALTER TABLE tasks ADD COLUMN budget_max_wall_secs INTEGER;
ALTER TABLE tasks ADD COLUMN budget_max_tokens    INTEGER;
ALTER TABLE tasks ADD COLUMN budget_steps_used    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN budget_wall_ms_used  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN budget_tokens_used   INTEGER NOT NULL DEFAULT 0;

CREATE TABLE task_dependencies (
    task_id             TEXT NOT NULL,
    depends_on_task_id  TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on_task_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (depends_on_task_id) REFERENCES tasks(task_id)
);
CREATE INDEX idx_tasks_parent ON tasks(parent_task_id);
CREATE INDEX idx_task_dependencies_dep ON task_dependencies(depends_on_task_id);
```

Explicit columns rather than a JSON budget blob so the limits can be enforced in
SQL and inspected by the operator without deserialisation.

### 4.4 Dependency gating (transactional, not advisory)

A child task is created in `Created`. Promotion is one statement:

```sql
-- inside a single transaction with the completion of a prerequisite
UPDATE tasks SET state = 'Ready', updated_at = ?
WHERE task_id = ?1
  AND state = 'Created'
  AND NOT EXISTS (
      SELECT 1 FROM task_dependencies d
      JOIN tasks t ON t.task_id = d.depends_on_task_id
      WHERE d.task_id = ?1 AND t.state <> 'Completed'
  );
```

If the update affects 0 rows, the dependency is unmet and nothing changes. A
prerequisite entering `Failed` or `Cancelled` does **not** silently unblock
dependents: they transition `Created → Blocked` with a recorded cause and require
an operator decision (same philosophy as Phase 5 re-queue).

Cycle detection at admission: DFS over the parent chain plus the dependency
edges, inside the creating transaction.

### 4.5 Admission control (`DelegationAdmission`)

The planner proposes; the runtime admits. A `TaskGraphProposal` is rejected if
any of:

* depth > `max_depth` (default 3) or fan-out > `max_children` (default 8);
* the sum of child budgets exceeds the parent's remaining budget;
* a child declares a capability the parent's grant does not cover (no
  privilege escalation — `capability_covers` per child capability);
* a dependency references a task outside the proposed graph or an ancestor;
* the objective/deliverable contract is empty.

Admission returns `DelegationPlan { admitted: Vec<TaskId>, rejected: Vec<(Index, Reason)> }`.
Partial admission is allowed only if the graph remains acyclic and budget-valid.

### 4.6 Budget

```rust
pub struct TaskBudget {
    pub max_steps: Option<u32>,
    pub max_wall_seconds: Option<u64>,
    pub max_tokens: Option<u64>,     // recorded, not yet enforced (see below)
    pub steps_used: u32,
    pub wall_ms_used: u64,
    pub tokens_used: u64,
}
```

* **Steps and wall time are enforceable now.** `ExecutorAgent` already tracks
  both (`AgentBudget`); the delegation kernel gives it the child's envelope and
  decrements the parent on completion.
* **Tokens are not enforceable yet.** `ModelProvider::propose_action` returns no
  usage data. 6.1 persists `max_tokens` and refuses to *create* a task with a
  token limit unless the configured provider declares usage reporting. Otherwise
  the limit is a lie. Enforcement lands in 6.2.
* Exhaustion: child → `Failed(BudgetExceeded)`, event to the parent, parent
  accounting updated in the same transaction.

### 4.7 Completion gate

```rust
pub struct DeliverableContract {
    pub required_artifacts: Vec<ArtifactSelector>, // artifact_type + metadata predicate
    pub require_verification: Option<VerificationRef>, // 6.4; None in 6.1
}

pub enum CompletionGateError {
    ChildNotComplete { child: Uuid, state: TaskState },
    DeliverableMissing { selector: ArtifactSelector },
    VerificationNotSatisfied { detail: String },
}
```

`TaskStore::complete_with_evidence(child, contract)` is the only path from
`Validating` to `Completed`. Model self-report is not an input: the executor's
`AgentLoopStatus::Completed` merely requests `Validating`.

Parent completion (`complete_parent`) additionally requires every child
`Completed`. A child `Failed`/`Cancelled` sends the parent to `Blocked`, never
`Completed`.

### 4.8 Cancellation cascade

`TaskStore::cancel_tree(root, actor, reason)`:

1. recursive CTE over `parent_task_id` collects descendants;
2. one transaction sets each non-terminal task to `Cancelled` and emits
   `TaskCancelled` with the root cause;
3. running executors observe cancellation by polling the task state between
   cycles. The loop already re-reads the grant every cycle
   (`get_active_grant_for_agent_task`); reading the task state at the same point
   is a small addition. No thread kill, no signal.

**Interaction with Phase 5, stated explicitly:** cancellation never resolves an
uncertain checkpoint. A cancelled task whose checkpoint is `Dispatched` is still
returned by `recover_all`; recovery marks the checkpoint `OutcomeUnknown` and
leaves the task terminal. Reconciliation can still adopt the outcome afterwards,
but no task in `Cancelled` may be resumed. This needs its own test
(`cancelled_task_with_uncertain_checkpoint_stays_cancelled`).

### 4.9 API surface

```rust
// kernel/src/delegation/
pub struct DelegationKernel { /* wraps TaskStore + EventBus */ }
impl DelegationKernel {
    pub fn create_child(&self, parent: Uuid, spec: ChildTaskSpec, admission: &AdmissionContext)
        -> Result<Uuid, DelegationError>;
    pub fn admit_graph(&self, parent: Uuid, proposal: TaskGraphProposal)
        -> Result<DelegationPlan, DelegationError>;
    pub fn children(&self, parent: Uuid) -> Result<Vec<Task>, DelegationError>;
    pub fn child_aggregate(&self, parent: Uuid) -> Result<ChildAggregate, DelegationError>;
    pub fn cancel_tree(&self, root: Uuid, actor: &AuthenticatedActor, reason: &str)
        -> Result<Vec<Uuid>, DelegationError>;
    pub fn charge_budget(&self, task: Uuid, usage: BudgetUsage) -> Result<TaskBudget, DelegationError>;
    pub fn promote_ready_children(&self, parent: Uuid) -> Result<Vec<Uuid>, DelegationError>;
}
```

No new process, no new bus, no new permission layer — it composes `TaskStore`,
`EventBus`, `PolicyEngine` and `GrantIssuer`.

---

## 5. Dependency map and order

### 5.1 Reuse map — what Phase 6 must not rebuild

Answering the "no second framework" warning concretely:

| Phase 6 need | Reused service | Genuinely new |
|---|---|---|
| Parent-child persistence | `tasks` table, `TaskStore` | M8 columns + module |
| Dependency gating | `transition_state_with_connection` | one SQL predicate + cascade |
| Budget | `AgentBudget` in the executor | persisted envelope + charge |
| Authorization | `PolicyEngine`, `GrantIssuer`, `capability_covers` | `SystemReconciliation` variant |
| Evidence | `EventBus`, `ArtifactRegistry` | probe trait + Git/FS probes |
| Workspace isolation | `RepositoryProvisioner` | hoist the governed wrapper down |
| Deliverables | `ArtifactRegistry`, `ArtifactRevisionStore` | selector contract only |
| Cancellation | task state + `EventBus` | recursive CTE |
| Crash recovery | `RecoveryEngine` | actor + evidence-spec changes |

Nothing in this list proposes a new scheduler, bus, permission layer, or
artifact store.

### 5.2 Build order

```
6.0 ─ identity types ──┬─> 6.0 reconcile(actor, spec) ──> M7 provenance
                       │            ▲
       capability ─────┘            │
       SystemReconciliation   probe trait + Git probe (tools)

6.1 ─ M8 schema ──> state machine (Validating, Cancelled) ──> dependency gate
                                                └────────────> admission control
                                                                     │
                                                       completion gate / cascade
                                                                     │
                                                        executor integration
```

Hard ordering constraints:

1. `AuthenticatedActor` must land **before** `reconcile` changes signature,
   otherwise we churn the API twice.
2. The probe trait must land **before** the harness is rewritten to use it, or we
   keep two reconcilers.
3. M8 and the state-machine additions must land **together**; a task row with
   `parent_task_id` but no `Validating` state cannot express the completion gate.
4. 6.1 must not start before 6.0's actor type exists, because `cancel_tree` takes
   an actor.

## 6. Decisions I need from you

| # | Decision | My recommendation |
|---|---|---|
| 1 | Actor authentication mechanism, and whether the host may add `libc` / `windows-sys` | `LocalProcessAuthenticator` in the host; kernel stays dependency-free; `Agent` actors unmintable |
| 2 | `SystemReconciliation` scope | ledger-scoped (`{ledger: PathBuf}`), consistent with every other capability |
| 3 | Dependency-blocked state | reuse `Created` + transactional promotion; do **not** overload `Waiting` |
| 4 | Token budget | persist in 6.1, enforce in 6.2 once `ModelProvider` reports usage; refuse to create token-limited tasks until then |
| 5 | Reconciler placement | runtime service, **not** in `export_schemas`, so agents have no surface |
| 6 | 6.1 home | `kernel/src/delegation/`, not a new crate |

## 7. Risks I want on the record

1. **M8 plus `Validating` touches the transition matrix that Phase 5's recovery
   depends on.** Every new edge must be re-tested against `Running→Blocked` and
   `Blocked→Ready`, or crash recovery regresses silently.
2. **Cancellation versus uncertain side effects** (§4.8) is the sharpest edge in
   the whole package. I have specified a rule; it needs adversarial tests before
   it is trusted.
3. **Budget accounting across processes** is not transactional with the child's
   own step counter. A crash between child execution and parent charge double-
   counts or loses budget. Mitigation: charge is derived from the child's
   checkpoint ledger on recovery, not from a counter incremented in memory.
   This needs a design note before 6.1 implementation.
4. **`actor_id` provenance in M7 is only as strong as the authenticator.** If
   Decision 1 lands on the static operator, the audit says "someone claiming to
   be operator-1", and the report must say so rather than implying otherwise.
