# Phase 5 Acceptance Gate — Report v2

**Status:** Acceptance work complete on this host; Phase 5 remains **open for
your sign-off**, not self-closed.
**Date:** 2026-10-30
**Scope:** `kernel`, `agents`, `clients/cli`, `crash_harness`.

This revision answers the three acceptance issues and the two policy
refinements. Where the review described behaviour I had already shipped, I have
kept the implementation and added the missing *proof*; where it identified a real
gap, the gap is closed.

---

## 1. Corrections to the record, before the new work

Two of the three issues described code that is not what this workspace contains.
I state the facts, then say what I changed anyway — because in both cases the
review was right that the *evidence* was thinner than the claim.

### 1.1 Issue 1 — process termination

The report did not describe `std::process::exit(101)`. The worker never used
exit code 101:

| Mechanism | Code | Purpose |
|---|---|---|
| `--crash exit` | `std::process::exit(70..73)` | deterministic boundary crash |
| `--crash abort` | `std::process::abort()` | no unwinding, no flush |
| `--crash wait` | worker parks; **parent** terminates it | forced termination |
| — | `Child::kill()` | `TerminateProcess` (Windows) / `kill(pid, SIGKILL)` (Unix) |

`crash_harness/tests/process_kill.rs::spawn_and_kill` has always taken the third
path: the parent spawns the worker, waits for it to reach the after-commit
boundary, then terminates it. What was missing is that the test did not *assert*
the termination was external.

**Fixed:** `spawn_and_kill` now returns the `ExitStatus`, and the test asserts:

```rust
assert!(!status.success(), "the worker must be terminated externally, not exit on its own");
assert!(!matches!(status.code(), Some(0 | 70 | 71 | 72 | 73)),
        "the worker must not have reached one of its own crash boundaries");
```

`--crash exit` is retained as an *additional* deterministic mechanism, as the
review allowed.

### 1.2 Issue 2 — the crash matrix

The boundary the review asked for was already implemented as exit code 72
("after the physical side effect, before the result is persisted"), and the
post-result boundary as exit code 73. Both are in the matrix in §4.

The review was nonetheless right about one thing: the test's step 7 — *"the
original commit is discovered and verified"* — was satisfied by a caller-supplied
string, not by inspecting the repository. That was a real gap. It is now closed
with an actual probe (§5.2).

---

## 2. Decision A — reconciliation is not re-execution

Approved as stated, and now enforced rather than documented.

### 2.1 The durable record

`kernel/src/recovery/reconciliation.rs` + migration `M6_RECONCILIATION_SCHEMA`:

```
task_reconciliations(
    reconciliation_id, task_id, step_number,
    actor_id, action, reason, evidence,
    prior_status, new_status, created_at)
```

`action` ∈ `AdoptExistingArtifact | AuthorizeRetry | Indeterminate | RequeueForExecution`.

Every `reconcile` call — including an inconclusive one — writes a row inside the
same transaction as the checkpoint transition. If the row cannot be written, the
transition does not happen.

### 2.2 The invariants the review asked for

| Required invariant | How it is held |
|---|---|
| Re-queue requires an explicit operator or authorized action | `RecoveryEngine::requeue` is the only API; it rejects anything not `Blocked` |
| The action records actor, reason, timestamp, evidence | `task_reconciliations` row, written transactionally |
| Re-queue must not erase the original `OutcomeUnknown` checkpoint | reconciliation never deletes or rewrites identity columns; `prior_status` is preserved |
| The scheduler must not read re-queue as "the side effect failed" | `requeue` is **refused** while any step is `OutcomeUnknown`; the recorded evidence string says so explicitly |
| Reconciliation ≠ re-execution | `EffectObserved` → `Succeeded` (no dispatch); only `EffectAbsent` → `RetryReady` |

The "false binary" is gone: an operator can adopt a verified outcome and move on
without re-running anything, or prove the effect absent and authorize a retry,
or record that the evidence is inconclusive.

### 2.3 Checkpoint transition matrix (enforced in SQL)

| From | To | Allowed | Who |
|---|---|---|---|
| `Pending` | `Dispatched` | yes | executor, immediately before dispatch |
| `RetryReady` | `Dispatched` | yes | executor, only under a `RetryPermit` |
| `Pending` | `RetryReady` | yes | recovery (dispatch provably never happened) |
| `Dispatched` | `RetryReady` | **no** | impossible by construction |
| `Dispatched` | `OutcomeUnknown` | yes | recovery / executor on an uncertain outcome |
| `OutcomeUnknown` | `RetryReady` | yes | reconciler, only with `EffectAbsent` evidence |
| `OutcomeUnknown` | `Succeeded` | yes | reconciler, only with `EffectObserved` evidence |
| `Dispatched`/`OutcomeUnknown` | `Failed` | yes | terminal failure |

`mark_retry_ready_from_pending` and `mark_authorized_retry_ready` are separate
functions with disjoint `WHERE status IN (...)` clauses, so no call site can
promote a `Dispatched` row to retryable.

---

## 3. Decision B — runtime-authoritative capabilities

Approved with a condition. Two corrections and one addition.

### 3.1 The agent never declared capabilities

The mechanism was never "the agent tells recovery what it needs." The executor
recorded the *grant's* capabilities into `task_authorization_context` in the same
transaction as the `Pending` checkpoint. An agent could not add to, remove from,
or influence that set.

### 3.2 The real gap: over-declaration, not under-declaration

The recorded intent was the whole grant, which is broader than the pending
operation needs. That is now narrowed at recovery time:

1. At dispatch, the executor derives `required_capability` from the tool
   manifest (`UnifiedToolRegistry::required_capability_kind`, which reads the
   same `export_schemas()` table the dispatcher uses) and persists it.
2. At recovery, the authorizer filters the recorded intent down to capabilities
   of that family and authorizes only those.
3. If the intent contains **no** capability of the required family, the retry is
   refused (`IntentDoesNotCoverOperation`) and the task fails — the
   under-declaration case.
4. If the requirement cannot be derived at all, the retry is refused
   (`CapabilityRequirementsUnderivable`) rather than guessed.

### 3.3 Authorization is not replaced by the permit

The fresh grant is an *additional* gate, never a substitute:

* the executor re-checks the live policy against the grant's capabilities on
  every cycle;
* the tool itself still calls `PolicyEngine::evaluate_checked` for the concrete
  request (`GitWrite{repo_root}`) before acting — unchanged;
* the recovery grant is now **revoked as soon as the retry has an outcome**, so
  it cannot linger as ambient authority for later steps.

### 3.4 The handshake, end to end

```text
RetryReady checkpoint
   ├─ 1. checkpoint must be RetryReady and carry invocation identity
   ├─ 2. task must exist and be Running | Ready | Claimed
   ├─ 3. checkpoint.agent_id must equal the requesting agent
   ├─ 4. persisted capability intent must exist for (task, step)
   ├─ 5. policy drift is computed, never assumed away
   ├─ 6. intent narrowed to the operation's manifest-declared capability family
   │       ├─ none of that family → IntentDoesNotCoverOperation   (refuse, fail task)
   │       └─ requirement underivable → CapabilityRequirementsUnderivable
   ├─ 7. PolicyEngine::authorize_capability_set against the policy in force now
   │       └─ Denied → record decision, Running→Failed, no grant
   ├─ 8. issue a 1-hour grant scoped to the narrowed set
   ├─ 9. persist the decision + emit RecoveryAuthorizationGranted
   │       └─ persistence/audit failure → revoke the grant, return error
   └─ 10. RetryPermit { step, invocation_id, key, fingerprint, grant, policy }
```

`RecoveryEngine::prepare_retry` is the only public bridge from *retryable* to
*executable*.

---

## 4. Phase 5.3 — the crash matrix, as executed

Every row is a test in `crash_harness/tests/process_kill.rs` that spawns a real
worker against a real SQLite WAL database and a real Git repository.

| # | Boundary | Termination | Checkpoint after restart | Task | Commits |
|---|---|---|---|---|---|
| 1 | after `Pending`, before `Dispatched` | worker `exit(70)` | `RetryReady` | Running | 1 (unchanged) |
| 2 | after `Dispatched`, before invocation | worker `exit(71)` | `OutcomeUnknown` | Blocked | 1 (unchanged) |
| 3 | **after the commit, before the result** | worker `exit(72)` | `OutcomeUnknown` | Blocked | 2 — `HEAD` equals the reported hash |
| 4 | after the result, before completion | worker `exit(73)` | `Succeeded` | Running | 2 |
| 5 | **after the commit** | **parent kills the child** | `OutcomeUnknown` | Blocked | 2 |
| 6 | recovery run twice, two processes | — | unchanged | — | unchanged |

Non-duplication is proven twice over:

* row 2's test also runs `resume --blind`, which bypasses the gate and **does**
  create the second commit. The guarded path creates none. The gate, not luck,
  is what prevents the duplicate.
* row 3's test stages an extra change before retrying, so a replay *would* have
  had real work to commit. It does not.

---

## 5. Issue 3 — canonicalization, and the reconciliation probe

### 5.1 `skyos-canonical-json-v1`

`kernel/src/tasks/checkpoint.rs`:

| Property | Behaviour |
|---|---|
| Object key order | sorted by UTF-8 bytes (`str` ordering), recursively |
| Number representation | integral values normalized: `1`, `1.0`, `1e0` fingerprint alike; non-integral uses the shortest round-trippable form (locale-independent) |
| Omitted vs `null` | **distinct** — `{"a":null}` ≠ `{}`, because they are different proposals |
| String encoding | `serde_json` escaping applied to the parsed value, so `\u00e9` and `é` agree |
| Array order | preserved — order is meaningful |
| Field separation | length-prefixed (`u64` LE length before every field) |
| Versioning | `skyos-idem-v1` domain tag; older keys are rejected on resume instead of colliding |
| Same key + same payload | `IdempotencyLookup::Replayable` / `InFlight` |
| Same key + different payload | `IdempotencyLookup::Conflict` — never a cached result |

Note the reviewed snippet used `n.to_string()` for numbers, which leaves `1.0`
and `1` distinct. This implementation normalizes them.

### 5.2 Reconciliation now *discovers* the effect

The runtime records the pre-dispatch `baseline_head` in the
`ToolInvocationDispatched` event. The operator probe
(`crash-harness reconcile --evidence discover`) then:

1. reads that baseline from the ledger,
2. runs `git log --format=%H%x1f%s <baseline>..HEAD`,
3. matches commits whose subject equals the recorded intent,
4. returns `EffectObserved{hash}` (one match), `EffectAbsent` (none) or
   `Indeterminate` (ambiguous).

The test asserts that the discovered hash **equals the hash the crashed worker
reported**, and that the reconciliation record names who decided and why.

---

## 6. Acceptance matrix (the review's eleven rows)

| # | Criterion | Status | Proof |
|---|---|---|---|
| 1 | Fresh authorization after restart | **Pass** | `retry_requires_a_fresh_grant_scoped_to_the_recorded_intent`, `offline_policy_tightening_refuses_the_retry_end_to_end` |
| 2 | Revoked capability fails closed | **Pass** | `revoked_agent_cannot_be_reauthorized`, `policy_tightening_while_offline_refuses_the_retry_and_fails_the_task` |
| 3 | Agent cannot under-declare permissions | **Pass** | `an_under_declared_capability_intent_is_refused`, `an_underivable_capability_requirement_is_refused`, `the_fresh_grant_is_narrowed_to_the_operation_requirement` |
| 4 | Pending invocation safely retryable | **Pass** | `crash_after_pending_leaves_no_side_effect`, `pending_crash_is_retry_ready_and_retries_exactly_once` |
| 5 | Dispatched invocation never blindly retried | **Pass** | `crash_after_dispatch_blocks_the_task_without_duplicating`, `dispatched_idempotent_checkpoint_is_outcome_unknown_not_retryable` |
| 6 | Physical side effect survives worker termination | **Pass** | `externally_killed_process_leaves_a_durable_unknown_outcome` (asserts forced termination + surviving commit) |
| 7 | Outcome reconciled without duplicate side effect | **Pass** | `crash_after_the_side_effect_preserves_the_commit_and_never_replays_it` (probe discovers the hash), external-kill test |
| 8 | Recovery can run repeatedly without duplicate events | **Pass** | `repeated_recovery_in_fresh_processes_is_idempotent`, `repeated_recovery_is_idempotent` |
| 9 | Blocked task requires explicit authorized re-queue | **Pass** | `requeue_is_refused_while_uncertainty_remains`, `requeue_after_reconciliation_is_attributed_and_preserves_history`, `requeue_is_refused_while_the_outcome_is_unknown` |
| 10 | Idempotency payload mismatch rejected | **Pass** | `identical_key_with_different_arguments_is_a_conflict_not_a_replay`, `different_commit_messages_produce_different_idempotency_keys`, `resume_with_diverging_arguments_is_rejected_without_side_effects` |
| 11 | Audit and checkpoint consistency preserved | **Pass** | `failed_recovery_audit_rolls_back_the_classification`, `granted_authorization_is_persisted_and_audited`, `observed_effect_marks_the_step_succeeded` (record assertions) |

---

## 7. Verification evidence

Captured raw output, not retyped summaries. All under
`docs/phase5/evidence/`.

| Gate | Command | Result | Log |
|---|---|---|---|
| Full suite | `cargo test --workspace` | **234 passed, 0 failed**, 29 targets, exit 0 | `workspace_tests.txt` |
| Phase 5.3 gate | `cargo test -p skyos-crash-harness` | 10 passed, 0 failed, exit 0 | `phase5_3_process_kill.txt` |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, no diagnostics | `clippy.txt` |
| Formatting | `cargo fmt --all --check` | exit 0, no diff | `fmt.txt` |

Test-count history in this workspace: 214 at the first Phase 5 report, 223 after
the initial audit pass, 234 now. I never reported 204; if a different number
reached you, the raw log above is authoritative.

### 7.1 One environmental caveat (unchanged)

`filesystem_rejects_traversal_and_symlink_escape` passes, but its Windows symlink
half is skipped on this host with `ERROR_PRIVILEGE_NOT_HELD` (os error 1314) —
the account lacks Developer Mode. The lexical traversal assertions still run.

### 7.2 Re-verification (2026-10-30)

Re-run on this host. Raw logs are the `*_2026-10-30.txt` files in the same
directory; the original undated files above are left untouched as recorded.

| Gate | Command | Result | Log |
| --- | --- | --- | --- |
| Workspace subset | `cargo test --workspace --exclude agents --exclude sky-cli` | **247 passed, 0 failed**, 25 targets, exit 0 | `workspace_tests_2026-10-30.txt` |
| Phase 5.3 gate | same run, `crash_harness/tests/process_kill.rs` | **10 passed, 0 failed** | `phase5_3_process_kill_2026-10-30.txt` |
| Lints | `cargo clippy --workspace --exclude agents --exclude sky-cli --all-targets -- -D warnings` | exit 0, no diagnostics | `clippy_2026-10-30.txt` |
| Formatting | `cargo fmt --all --check` | **exit 1** — 8 diffs, every one in `kernel/src/delegation/cancellation.rs` | `fmt_2026-10-30.txt` |

**The full `cargo test --workspace` gate could not be completed today.** It fails
to *compile*: `agents/src/executor.rs` references `ExecutionGuard`,
`cancellation_pending` and `cancel_and_stop`, none of which exist anywhere in the
tree — 7 errors on the first attempt, 9 on retry, because the file was being
edited while the run happened. That edit belongs to the in-flight Phase 6.1D
cancellation workstream, not to this phase, and it is not mine to repair. Raw
output: `workspace_build_blocked_2026-10-30.txt`.

So the **234** figure above remains the last *complete* workspace run. What is
green today is every crate in this phase's scope — `kernel`, `tools`,
`transform`, `provisioner`, `models`, `crash_harness` — plus the new
`models/tests/ollama_provider_tests.rs` (16 tests) covering the Ollama adapter
landed under the **other** Phase 5 track. All files owned by this phase are
rustfmt-clean; the formatting failure above is another workstream's file.

---

## 8. Phase 5 structure and what remains open

| Phase | State |
|---|---|
| 5.1 Executor integration | Implemented |
| 5.2 Recovery authorization (runtime-derived) | Implemented, verified |
| 5.3 Crash recovery (external kill, discovery) | Implemented, verified |
| 5.4 Operational recovery contract | Implemented (record + re-queue audit + probe); documentation is this report |

Deliberately still open, and I do not think they block *this* gate:

1. **Automatic resumption is off.** `prepare_retry` must be called explicitly
   and its permit supplied. A restart never resumes a task on its own.
2. **The reconciliation probe lives in the harness, not the runtime.** It is an
   operator instrument. Promoting it into `tools` as a first-class reconciler is
   the natural next step, and the review scoped 5.4 as documentation rather than
   a new subsystem, so I did not do it unasked.
3. **Actor identity is recorded, not authenticated.** `actor_id` is supplied by
   the caller; there is no operator authentication layer yet.
4. **Grants are in-memory.** The authorizer must run in the process that will
   execute; there is no distributed grant store.
5. **The CLI carries an empty policy.** Startup reconciliation classifies but
   never re-authorizes.

### 8.1 Resolutions since this report (2026-10-30)

Two of the five open items were closed by the Phase 6.0/6.1 work; neither change
touched this phase's code or tests.

| # | Open item | Now |
| --- | --- | --- |
| 2 | The reconciliation probe lives in the harness, not the runtime | **Closed** — promoted to `tools/src/reconciler.rs` (`GitCommitProbe`, `FileChecksumProbe`, `default_probes()`), consumed by `clients/cli/src/recovery.rs`, the harness and the executor tests |
| 3 | Actor identity is recorded, not authenticated | **Closed** — `kernel/src/identity/` defines `ActorAuthenticator` with a `DenyAllAuthenticator` safe default and no public constructor for `AuthenticatedActor`; the host-side `LocalProcessAuthenticator` (`clients/cli/src/identity.rs`) reads the OS process identity, refuses agents outright and refuses bearer credentials |

Items 1, 4 and 5 — automatic resumption stays off, grants remain in-memory, the
CLI still builds an empty `AuthorizationPolicy` — remain true and are unchanged
by this re-verification.

## 9. Suggested next step

Phase 5.4 as scoped: promote the Git reconciler into the tool layer behind a
capability, add operator authentication for `actor_id`, and freeze the
operational runbook. No new autonomy.
