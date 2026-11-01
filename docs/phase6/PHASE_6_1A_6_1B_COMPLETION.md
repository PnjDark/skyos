# Phase 6.0 prerequisites + Phase 6.1A/6.1B — Completion

**Status:** implemented and verified on this host.
**Date:** 2026-10-30
**Baseline:** Phase 6.0 locked at 260 tests; this package closes its two
operational gaps and lands the delegation persistence layer.

---

## 1. Phase 6.0 operational prerequisites

### 1.1 Host OS process authentication

`clients/cli/src/identity.rs` now ships `LocalProcessAuthenticator`, which reads
the real OS identity:

| Platform | Mechanism | Reported method |
|---|---|---|
| Windows | `OpenProcessToken` → `GetTokenInformation(TokenUser)` → `ConvertSidToStringSidW` | `LocalProcess { platform_id: "win-sid:S-1-5-…" }` |
| Unix | `getuid` | `LocalProcess { platform_id: "unix-uid:1000" }` |
| other | none | verification **fails** |

Three deliberate properties:

* **No silent downgrade.** If the platform call fails, verification fails with
  "refusing to fall back to the environment". `EnvironmentClaimed` is produced
  only by the separate `HostOperatorAuthenticator`, which is no longer the
  default anywhere.
* **Buffer alignment.** The token buffer is `Vec<u64>` rather than `Vec<u8>`,
  because `TOKEN_USER` contains pointers and a byte buffer would only guarantee
  alignment 1.
* **Platform dependencies stay in the host.** `windows-sys` and `libc` are
  target-scoped dependencies of `sky-cli`; `kernel` remains platform-agnostic and
  compiles with no platform crates.

The tests assert the identity is marked verified, that the identifier has the
expected platform shape (`win-sid:` / `unix-uid:`), and that a claimed id must
match the process identity.

### 1.2 `sky recovery reconcile`

```
sky recovery reconcile <TASK_ID> <STEP_NUMBER> \
    --invocation-id <UUID> \
    --evidence '{"kind":"git_commit","repo_root":".","intent_message":"msg"}' \
    [--reason "..."] [--actor "..."]
```

Implemented in `clients/cli/src/recovery.rs` (`reconcile_invocation`), wired
through `main.rs`.

| Requirement | How it is met |
|---|---|
| Invokes the existing engine | calls `RecoveryEngine::reconcile`, no parallel path |
| Authenticated actor | `LocalProcessAuthenticator`, and the grant is minted for the **verified** id |
| Explicit grant | `issue_grant(verified.id, task, [SystemReconciliation{task}], 5 min)` |
| Evidence is a spec, never a verdict | `parse_evidence_spec` accepts `kind` + parameters only; a verdict-shaped argument is rejected |
| Identity consistency | `task_id` + `step_number` + `invocation_id` are checked against the persisted checkpoint **before** any probe runs |
| Durable record | one `task_reconciliations` row with actor, method, verdict, observation, grant |
| Audit | `InvocationReconciled`, `PermissionGranted`, and `CapabilityAuthorized`-family events in the WAL ledger |

`baseline_commit` may be omitted: the CLI then uses the baseline the runtime
recorded before dispatch. The engine still checks it, so the operator cannot
manufacture a convenient "after" state.

---

## 2. Phase 6.1A — Delegation persistence

`kernel/src/delegation/` — a kernel module, not a crate, so it composes
`TaskStore`, `EventBus` and the existing `tasks` table.

### 2.1 Schema (M8)

```sql
ALTER TABLE tasks ADD COLUMN parent_task_id    TEXT;
ALTER TABLE tasks ADD COLUMN assigned_agent_id TEXT;
ALTER TABLE tasks ADD COLUMN objective         TEXT;

CREATE TABLE task_dependencies (
    dependent_task_id    TEXT NOT NULL,
    prerequisite_task_id TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    PRIMARY KEY (dependent_task_id, prerequisite_task_id),
    FOREIGN KEY (dependent_task_id)    REFERENCES tasks(task_id),
    FOREIGN KEY (prerequisite_task_id) REFERENCES tasks(task_id)
);
```

Edge direction is fixed: `dependent -> prerequisite` means *dependent may not run
until prerequisite is Completed*.

### 2.2 Cycle rejection

`insert_dependency` runs a recursive CTE over the prerequisite closure inside the
creating transaction:

```sql
WITH RECURSIVE ancestors(task_id) AS (
    SELECT prerequisite_task_id FROM task_dependencies WHERE dependent_task_id = ?1
    UNION
    SELECT td.prerequisite_task_id FROM task_dependencies td
    JOIN ancestors a ON td.dependent_task_id = a.task_id
)
SELECT COUNT(*) FROM ancestors WHERE task_id = ?2
```

Adding `D -> P` is refused when `D` is already an ancestor of `P`. Self-edges and
unknown prerequisites are refused before the CTE runs. Because the check and the
insert share one transaction, a rejected edge writes nothing — asserted by
counting edges before and after.

---

## 3. Phase 6.1B — Readiness gate

`Created -> Ready` is a single conditional `UPDATE` evaluated inside the caller's
transaction:

```sql
UPDATE tasks SET state = 'Ready', updated_at = ?
WHERE task_id = ?1 AND state = 'Created'
  AND NOT EXISTS (
      SELECT 1 FROM task_dependencies d
      JOIN tasks t ON t.task_id = d.prerequisite_task_id
      WHERE d.dependent_task_id = ?1 AND t.state <> 'Completed'
  )
```

If zero rows change, the task stays `Created`; readiness is never assumed.
`Waiting` keeps its existing meaning (agent paused mid-execution) and is not
reused here.

`complete_task(task_id)` performs the completion transition **and** the release of
every eligible dependent in one transaction, returning the ids it released. An
unrelated running task is untouched.

---

## 4. Deviations from the proposal

1. **No `delegated_tasks` table.** The proposal listed both `delegated_tasks` and
   `task_dependencies`. The task row already carries identity, state and
   timestamps; a second table would make two sources of truth for one task. The
   delegation columns were added to `tasks` instead, and `task_dependencies`
   holds only edges.
2. **Completion release lives in `DelegationKernel::complete_task`.** The
   proposal asked for readiness to be transactional with completion; putting the
   promotion anywhere else (e.g. in `TaskStore`) would have let a caller complete
   a task without releasing its dependents.
3. **Package name.** The verification command `cargo test -p skyos-kernel` does
   not resolve here — the crate is `kernel`.

---

## 5. Verification

| Gate | Command | Result | Log |
|---|---|---|---|
| Full suite | `cargo test --workspace` | **277 passed, 0 failed**, 31 targets | `evidence/workspace_tests.txt` |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 | `evidence/clippy.txt` |
| Formatting | `cargo fmt --all --check` | exit 0 | `evidence/fmt.txt` |
| Delegation gate | `cargo test -p kernel --test delegation_tests` | 10 passed | `evidence/delegation_gate.txt` |
| Operator command | `cargo test -p sky-cli --test reconcile_gate_tests` | 5 passed | `evidence/reconcile_command.txt` |
| Phase 5.3 gate | `cargo test -p skyos-crash-harness` | 10 passed | `evidence/phase5_3_gate_still_green.txt` |

260 → 277 = **17 new tests**:

**Delegation (10)** — child creation under a parent; a dependent stays `Created`
while its prerequisite runs; unknown prerequisite rejected with no partial row;
self-dependency rejected; completion releases exactly its dependents; a
two-prerequisite dependent is not released early; a cycle is rejected with zero
edge writes; a three-node cycle is rejected; the DAG, edges and readiness survive
a restart; delegation and readiness are in the audit ledger.

**Operator command (5)** — the command records a durable decision from a real Git
probe (record fields asserted, including `LocalProcess` and the recorded
baseline); a wrong `invocation_id` is refused and changes nothing; a
verdict-shaped `--evidence` is rejected; a proven-absent effect yields
`RetryReady` with `ConfirmedNotExecuted`; the engine still denies a grant scoped
to another task.

**Identity (2 net)** — process identity is verified and platform-shaped; a
claimed identity must match it.

---

## 6. What is deliberately not here

* **6.1C budget accounting.** Blocked on the design note you required: a single
  append-only charge record keyed by `invocation_id`, with checkpoints
  referencing state rather than duplicating charges. Not started.
* **6.1D cancellation, 6.1E `Validating`.** Not started; the state machine still
  has no `Cancelled` or `Validating`.
* **Token budget.** Unchanged decision: persisted, rejected at creation while
  usage reporting is unsupported, enforced in 6.2.
* **Admission control** (depth, fan-out, budget sum) belongs with 6.1C — it needs
  the budget model to exist first.
