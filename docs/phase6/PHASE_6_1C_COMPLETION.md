# Phase 6.1C — Budget Accounting: Completion

**Status:** implemented and verified on this host.
**Scope:** the five authorized stages (M9 → concurrency gates). No executor
integration, no cancellation, no deliverable validation.

---

## 1. What shipped

| Stage | Deliverable | Where |
|---|---|---|
| 6.1C.1 | Migration M9: `task_budgets`, `task_budget_ledger`, partial unique indexes | `kernel/src/persistence/migrations.rs` |
| 6.1C.2 | Ledger, exposure (supersession), signed adjustments, idempotency | `kernel/src/delegation/budget.rs` |
| 6.1C.3 | `BEGIN IMMEDIATE` child allocation against the parent envelope | `delegation/budget.rs` + `delegation/store.rs` |
| 6.1C.4 | Settlement, zero-settlement for provably-undispatched work, recovery-bound duration | `delegation/budget.rs` |
| 6.1C.5 | Crash matrix (6) + concurrency gates (5) | `kernel/tests/budget_*_tests.rs` |

One authority: `task_budget_ledger` owns token/time exposure; checkpoints own
execution state. Neither is derived from the other.

---

## 2. Exposure is supersession

```text
exposure(invocation) = sum(adjustments) + COALESCE(settlement, reservation, 0)
```

Implemented in one SQL aggregate per invocation, then summed per task. Tests pin
the two directions that matter:

* `a_settlement_supersedes_its_reservation` — 400 reserved, 120 settled, exposure
  is 120, not 520.
* `crash_after_settlement_before_the_checkpoint_does_not_double_count` — a
  recovery pass seeing only `Dispatched` must not re-add the reservation.

Adjustments are signed and additive: `adjustments_are_signed_and_added_once`
(100 settled, +50, −20 → 130, four rows, none replaced).

---

## 3. Crash matrix — as executed

| # | Boundary | Test | Result |
|---|---|---|---|
| 1 | before reservation | `crash_before_reservation_charges_nothing` | no row, exposure 0 |
| 2 | after reserve, before dispatch | `crash_after_reservation_before_dispatch_releases_it` | zero-settlement supersedes; exposure 0; the reservation row is preserved |
| 3 | after dispatch | `crash_after_dispatch_retains_the_reservation` | exposure = reservation (tokens and timeout) |
| 4 | after settlement, before checkpoint | `crash_after_settlement_before_the_checkpoint_does_not_double_count` | exposure = settlement |
| 5 | reconciliation adjustments | `adjustments_are_signed_and_added_once` | deltas applied once, append-only |
| 6 | after checkpoint success | `crash_after_checkpoint_success_is_stable` | stable across repeated reads |

Boundary 2 needed a decision: the ledger is append-only, so "release" is not a
delete. A zero `Settlement` with the reason *"checkpoint was pending: the tool
provably never ran"* supersedes the reservation and keeps the history legible.

---

## 4. Concurrency gates — as executed

| Gate | Test | Result |
|---|---|---|
| Parent oversubscription | `concurrent_child_allocations_cannot_oversubscribe_the_parent` | 8 threads × 600 into a 1,000 envelope → exactly 1 wins |
| Duplicate reservation | `concurrent_reservations_for_one_invocation_yield_one_row` | 8 identical attempts → 1 row, 250 exposure |
| Duplicate settlement | `concurrent_settlements_yield_one_row` | 6 attempts → 1 row, 120 exposure |
| Settle racing a read | `settlement_racing_an_exposure_read_is_counted_once` | readers see reservation *or* settlement, never a sum |
| Unresolved sibling | `an_unresolved_sibling_holds_budget_against_release` | terminal+resolved child releases to settled usage; unresolved child holds its allocation; one of two late 300-token allocations fits the remaining 500 |

Making these meaningful required a change outside the budget module: **every
connection now sets `PRAGMA busy_timeout = 5000`**. Without it SQLite returns
`SQLITE_BUSY` immediately instead of waiting for the write lock, and the
oversubscription test would exercise the error path rather than the lock.

---

## 5. Parent-child accounting

`child_committed` is the single rule:

* terminal (`Completed`/`Failed`) **and** fully resolved → contributes settled
  usage;
* otherwise → contributes its allocation.

So an active child occupies its parent's envelope by its *allocation*, never its
allocation plus its usage. `nested_delegation_rolls_up_without_double_counting`
pins the three-level case: parent commits the child's 400, the child commits the
grandchild's 100, and a grandchild settlement releases 70 back to the **child**,
not to the grandparent.

---

## 6. Deviations from the approved blueprint

1. **The dispatch timeout is stored on the reservation row, not in the
   `Dispatched` event payload.** Both are durable; the reservation is written
   *before* the effect can occur, which is strictly earlier than dispatch, and it
   is the record that needs the bound. The dispatch instant comes from
   `task_checkpoints.checkpoint_time`, written by the same `UPDATE` that sets
   `status = 'Dispatched'` — so it is the dispatch time by construction. Neither
   value is read from current configuration, which was the actual requirement.
2. **No `Release` entry kind.** Release is expressed as settlement supersession
   (a zero settlement when the work provably never ran, the settled amount
   otherwise), which removes the crash window where a settlement lands and a
   release row does not.
3. **The ledger is its own audit.** Budget rows carry actor, reason, timestamp
   and idempotency key; no parallel event is emitted, so there is no second copy
   to drift.
4. **A settlement may exceed its reservation** (a provider can overshoot). It is
   recorded truthfully; subsequent reservations see the larger exposure and fail
   their envelope check. It is not silently clamped, because clamping would hide
   a budget breach.

---

## 7. Verification

| Gate | Command | Result | Log |
|---|---|---|---|
| Full suite | `cargo test --workspace` | **309 passed, 0 failed**, 34 targets | `evidence/workspace_tests.txt` |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 | `evidence/clippy.txt` |
| Formatting | `cargo fmt --all --check` | exit 0 | `evidence/fmt.txt` |
| Budget ledger | `cargo test -p kernel --test budget_tests` | 19 passed | `evidence/budget_crash_matrix.txt` |
| Concurrency | `cargo test -p kernel --test budget_concurrency_tests` | 5 passed | `evidence/budget_concurrency.txt` |
| Delegation | `cargo test -p kernel --test delegation_tests` | 10 passed | `evidence/delegation_gate.txt` |
| CLI gate | `cargo test -p sky-cli --test cli_process_reconcile_tests` | 8 passed | `evidence/cli_process_gate.txt` |
| Phase 5.3 gate | `cargo test -p skyos-crash-harness` | 10 passed | `evidence/phase5_3_gate_still_green.txt` |

285 → 309 = **24 new tests** (19 ledger/crash, 5 concurrency).

---

## 8. Deliberately not done

* **Executor integration.** `ExecutorAgent` does not yet take a reservation before
  dispatch. The ledger and lifecycle exist and are tested at the kernel boundary;
  wiring them into the agent loop is the next step, and it should land with the
  token decision below rather than before it.
* **Token enforcement.** Unchanged decision: token-limited task creation stays
  rejected until the provider reports usage. The ledger stores token amounts;
  nothing fabricates them.
* **`Cancelled` and `Validating`.** Still absent. Your ruling is explicit that
  cancellation must not release budget while a worker may still be active, so
  6.1D inherits the hold rule rather than re-deriving it.
* **Cost/money budget.** No price source exists; recording it would be invented.
