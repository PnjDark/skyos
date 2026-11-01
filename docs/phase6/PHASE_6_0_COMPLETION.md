# Phase 6.0 — Governed Reconciliation & Authenticated Identity

**Status:** implemented and verified on this host. Phase 5 remains locked; no
6.1 code was started.
**Date:** 2026-10-30
**Evidence:** `docs/phase6/evidence/`

---

## 1. What shipped

| Deliverable | Where |
|---|---|
| Unforgeable authenticated actor | `kernel/src/identity/mod.rs` |
| `Capability::SystemReconciliation { task_id }` | `kernel/src/permissions/types.rs`, `policy.rs`, `engine.rs` |
| Probe-driven evidence contract | `kernel/src/recovery/evidence.rs` |
| Reconciler probes (Git, file digest) | `tools/src/reconciler.rs` |
| Engine authenticates, runs the probe, derives the verdict | `kernel/src/recovery/mod.rs` |
| Provenance ledger (migration M7) | `kernel/src/recovery/reconciliation.rs`, `migrations.rs` |
| Host authenticator | `clients/cli/src/identity.rs` |

The Phase 5 API accepted a caller-supplied verdict
(`ReconciliationEvidence::EffectObserved`). That is gone. A caller now names an
observation; the runtime collects the fact and derives the conclusion.

---

## 2. The three barriers

`RecoveryEngine::reconcile(claim, grant, request)` passes through all three
before it touches the ledger:

1. **Authentication happens in the kernel.** The caller passes an
   `ActorClaim`; the engine runs the configured `ActorAuthenticator` and builds
   the `AuthenticatedActor` itself via the crate-private constructor. No other
   crate can produce that type, so a host cannot hand the engine a pre-blessed
   actor.
2. **Agents are refused outright.** `ActorKind::Agent` →
   `RecoveryError::AgentSelfReconciliation`, regardless of the grant.
3. **Authority must be presented and scoped.** The grant must belong to the
   authenticated actor, must be active, and must carry
   `SystemReconciliation { task_id }` for exactly this task — checked through the
   audited `PolicyEngine`, so the authorization decision is itself in the event
   ledger.

A fourth check bounds the *observation*: the request's `baseline_commit` must
equal the baseline the runtime recorded in the `ToolInvocationDispatched` event.
A caller cannot nominate a convenient "after" state and manufacture absence.

---

## 3. Verdict derivation is not caller-controlled

`kernel/src/recovery/evidence.rs::evaluate` is the only place a verdict is
produced, and it is deliberately asymmetric:

| Observation | Verdict |
|---|---|
| Git: exactly 1 matching commit | `ConfirmedSucceeded` |
| Git: 0 matching commits | `ConfirmedNotExecuted` |
| Git: >1 matching commits | `Indeterminate` |
| File: digest matches | `ConfirmedSucceeded` |
| File: digest differs or file absent | `Indeterminate` |
| Any malformed/absent count | `Indeterminate` |

`ConfirmedNotExecuted` is the verdict that unlocks a retry, so it is only ever
produced when the runtime bounded the range itself.

---

## 4. Deviations from the approved spec

Recorded rather than hidden.

### 4.1 `LocalProcessAuthenticator` → `HostOperatorAuthenticator`

The approved design named a `LocalProcessAuthenticator`. Implementing it
honestly needs the process token (`GetTokenInformation` on Windows,
`getuid` on Unix), which means adding `windows-sys` / `libc` to the host.
**Decision 1 (may the host add platform dependencies?) was never answered.**

Rather than ship an environment lookup labelled "local process identity", the
CLI now uses `HostOperatorAuthenticator`, which binds the actor to the OS user
and host and records the method as `EnvironmentClaimed`. The audit trail
therefore says exactly what was verified. `AuthMethod::LocalProcess` exists in
the type but is not produced by any shipped authenticator.

Consequence: the actor is *attributable* to a local user, not cryptographically
verified against the process token. Everything else the security model depends
on — the agent ban, the unforgeable type, capability scoping — does not rely on
this method.

### 4.2 `reconcile` also takes the grant

The spec's signature was `reconcile(claim, request)`. The implementation is
`reconcile(claim, grant, request)`.

Reason: the authorization input should be visible at the call site and recorded
in the audit (`grant_id` is now stored per decision). Looking up "some active
grant for this actor and task" inside the engine would hide which authority was
exercised. Same for `requeue`.

### 4.3 Capability scope is task-scoped

Implemented as `SystemReconciliation { task_id }` per your directive. My earlier
recommendation was ledger-scoped; task scoping is strictly narrower and is the
better choice — an operator reconciling one crashed task cannot thereby
reconcile every other task in the same runtime.

### 4.4 The baseline lives in an event, for now

`recorded_baseline` reads the `ToolInvocationDispatched` event payload. Phase 6.1
should promote it into `task_authorization_context` so the baseline is written
in the same transaction as the checkpoint rather than as an event side-channel.

---

## 5. Migration M7

`task_reconciliations` gains `invocation_id`, `verdict`, `evidence_kind`,
`evidence_source`, `evidence_json`, `actor_kind`, `auth_method`, `grant_id`.

Applied to existing databases with `ALTER TABLE` via `ensure_column`. A row whose
provenance columns are NULL predates probe-driven reconciliation and must not be
read as independently verified — the reader returns empty strings, not
fabricated values.

---

## 6. Verification

| Gate | Command | Result | Log |
|---|---|---|---|
| Full suite | `cargo test --workspace` | **260 passed, 0 failed**, 29 targets | `workspace_tests.txt` |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, no diagnostics | `clippy.txt` |
| Formatting | `cargo fmt --all --check` | exit 0, no diff | `fmt.txt` |

260 − 234 = **26 new tests**, all adversarial or contract-level:

**Identity (4)** — verified identity carries the authenticator's verdict;
an authenticator can refuse agents; `DenyAllAuthenticator` never verifies; an
environment-derived method is not reported as verified.

**Verdict derivation (6)** — one match confirms; zero confirms absence; two are
indeterminate; a probe reporting nothing is indeterminate; a checksum mismatch
never proves absence; mismatched evidence kinds are indeterminate.

**Probes (4)** — real `git log` against a real repository: zero matches,
one matching commit, unreadable repo is an error not a verdict, file digest
match/mismatch/missing.

**Governed reconciliation (9)** — `agent_actor_cannot_reconcile_its_own_operation`,
`reconciliation_capability_is_scoped_to_one_task`,
`a_grant_issued_to_another_actor_cannot_be_borrowed`,
`an_expired_reconciliation_grant_is_refused`,
`a_caller_cannot_nominate_a_baseline_the_runtime_never_recorded`,
`reconciliation_without_a_probe_is_refused`,
`an_unauditable_reconciliation_changes_nothing`,
`reconciliation_records_authenticated_provenance`,
`a_probe_that_observes_nothing_cannot_unblock_a_retry`.

The Phase 5.3 process-kill gate still passes unchanged (10/10), including
external termination and duplicate-commit prevention — the reconciliation step in
those tests now goes through the probe and the capability gate.

---

## 7. What is still open from the 6.0 scope

1. **Token-backed identity.** See §4.1. Needs Decision 1.
2. **Baseline promotion** into the authorization context (§4.4), scheduled for 6.1.
3. **The CLI has no `recovery reconcile` command.** The engine API is complete
   and exercised by the harness; the operator-facing command is not wired. This
   is the natural first task of 6.1's operator surface, or a small 6.0.1.
4. **`SystemReconciliation` is not in `export_schemas`** — deliberate, so agents
   never see it as a tool.

## 8. Suggested next step

6.1 (delegation kernel) per the approved interface spec, starting with the M8
schema and the `Validating`/`Cancelled` transitions — but not until Decision 1
is answered, since the same identity type is the actor for `cancel_tree`.
