# Phase 6.1C — Budget Accounting Design (proposal, implementation blocked)

**Status:** design proposal for sign-off. **No budget code has been written.**
**Scope:** reservation/settlement accounting, parent-child allocation, recovery.

This note answers the eight points required before implementation, and records
three places where I would change the draft schema rather than implement it as
written.

---

## 1. The crash window the draft did not close

> A provider charges for an operation; the worker dies before the charge row is
> written; recovery sees `OutcomeUnknown` and no charge.

A charge table keyed by `invocation_id` prevents *double* counting. It cannot
prevent *lost* counting, because the row that would record the loss is exactly
the row that never got written.

The fix is not a better charge table. It is to make the runtime commit to a
**maximum** before the effect can happen:

```
reserve  →  dispatch  →  settle
   ↑                        ↑
   └── before any effect    └── only when usage is trustworthy
```

If the process dies anywhere after `reserve`, the reservation is already durable
and is retained. A lost settlement can under-charge relative to actual usage, but
it can never *under-reserve*. That is the asymmetry that makes the accounting
crash-safe.

---

## 2. Three-phase lifecycle

| Phase | When | Durable effect |
|---|---|---|
| **Reserve** | in the same transaction as the `Pending` checkpoint, before dispatch | one `Reservation` entry for `(task, invocation)` |
| **Settle** | when the outcome and usage are both durable | one `Settlement` entry; the reservation is implicitly released |
| **Retain** | process died after reserve | nothing is written; the reservation stands |

A reservation is not a charge. It is the maximum the runtime has already
committed to spend. Treating "reserved" and "charged" as the same event is what
leaves the crash window open.

---

## 3. Schema — with three corrections

### 3.1 Correction 1: `UNIQUE(invocation_id, entry_kind)` is too strict

The draft allows one row per `(invocation, kind)`. That forbids multiple
`Adjustment` rows, which is exactly what resolving an uncertain charge needs. It
also invites a separate `Release` row, which creates a new crash window: settle
succeeds, release never happens, unused budget leaks silently.

**Proposal:** drop `Release` (a settlement supersedes its reservation, so the
difference is the release) and enforce uniqueness with **partial indexes** so
adjustments can repeat.

```sql
CREATE TABLE IF NOT EXISTS task_budget_ledger (
    entry_id            TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL,
    invocation_id       TEXT NOT NULL,
    entry_kind          TEXT NOT NULL
                        CHECK (entry_kind IN ('Reservation', 'Settlement', 'Adjustment')),
    tokens              INTEGER NOT NULL DEFAULT 0,
    observed_elapsed_ms INTEGER NOT NULL DEFAULT 0,
    elapsed_source      TEXT NOT NULL DEFAULT 'none',   -- 'worker' | 'recovery_bound' | 'none'
    actor_id            TEXT NOT NULL,                  -- 'runtime' or an authenticated actor
    reason              TEXT NOT NULL,
    recorded_at         TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

-- Exactly one reservation and one settlement per invocation; adjustments are
-- append-only and may repeat.
CREATE UNIQUE INDEX IF NOT EXISTS ux_budget_reservation
    ON task_budget_ledger(invocation_id) WHERE entry_kind = 'Reservation';
CREATE UNIQUE INDEX IF NOT EXISTS ux_budget_settlement
    ON task_budget_ledger(invocation_id) WHERE entry_kind = 'Settlement';
CREATE INDEX IF NOT EXISTS ix_budget_task ON task_budget_ledger(task_id);
```

### 3.2 Correction 2: exposure is supersession, not addition

For each invocation:

```
exposure(inv) = (Σ adjustments) + COALESCE(settlement.tokens, reservation.tokens, 0)
```

A settlement **replaces** its reservation; it does not add to it. Writing
`reservation + settlement` would double-count every successfully settled
operation — the same mistake the review warned about, inverted.

### 3.3 Correction 3: elapsed time must be captured at recovery, not at review

Wall-clock duration is not provider time and not worker CPU time. The only honest
label is **observed elapsed between durable dispatch and durable outcome**. But
for an uncertain invocation, measuring at *reconciliation* time inflates the
value by however long the task sat blocked — potentially days.

**Proposal:** classify the source explicitly:

| Situation | `elapsed_source` | Value |
|---|---|---|
| normal settlement | `worker` | `settled_at − dispatched_at` |
| outcome unknown | `recovery_bound` | `recovery_started_at − dispatched_at`, capped at the operation timeout |
| never dispatched | `none` | 0 |

The cap is what makes the bound defensible: the process cannot have executed
longer than the timeout it was dispatched under.

`dispatched_at` must come from the durable `Dispatched` checkpoint timestamp —
never from an in-memory counter.

---

## 4. Envelopes and the parent-child rule

```sql
CREATE TABLE IF NOT EXISTS task_budgets (
    task_id       TEXT PRIMARY KEY,
    max_tokens    INTEGER,          -- NULL = no token budget declared
    max_elapsed_s INTEGER,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
```

Child allocations are **derived**, not stored twice:

```sql
SELECT COALESCE(SUM(cb.max_tokens), 0)
FROM task_budgets cb
JOIN tasks t ON t.task_id = cb.task_id
WHERE t.parent_task_id = ?1;
```

Available budget for a parent is `max_tokens − Σ(child allocations) − Σ(exposure
of the parent's own invocations)`. Storing the allocation separately would create
two sources of truth that drift the moment a child is cancelled.

### 4.1 The oversubscription race

Two workers creating a child against the same parent can both read the same
`available` and both succeed. A `BEGIN DEFERRED` transaction does **not** prevent
this: the read happens before the write lock is taken.

**Requirement:** reservation transactions use `BEGIN IMMEDIATE`
(rusqlite: `transaction_with_behavior(TransactionBehavior::Immediate)`), so the
write lock is held for the whole check-then-insert. This is a hard requirement,
not an optimisation.

### 4.2 Release rules

1. A child's allocation is reserved from the parent **in the creation
   transaction**.
2. A child cannot reserve beyond its own envelope.
3. Settlement happens **exactly once** per invocation; a second attempt is
   idempotent, not additive.
4. Unused allocation returns to the parent **only** when the child is terminal
   (`Completed`/`Failed`) *and* it has no unresolved invocations.
5. `Blocked`, `OutcomeUnknown`, or any retained reservation holds the allocation.
6. Consumption and outstanding reservations are always derived from the ledger,
   never from memory.

---

## 5. Idempotency

| Operation | Repeated call | Conflicting call |
|---|---|---|
| Reserve | returns the existing reservation if the amount matches | different amount → `BudgetConflict`, no write |
| Settle | returns the existing settlement if the amount matches | different amount → `BudgetConflict`, no write |
| Adjust | new entry with a new `entry_id`; append-only | — |

This mirrors the Phase 5 idempotency-key rule: same key + same payload is the
same operation; same key + different payload is a hard conflict, never a silent
overwrite.

Reconciliation of an uncertain charge writes an `Adjustment` with the operator's
authenticated identity and reason — reusing the Phase 6.0 actor contract.

---

## 6. Token limits versus duration limits

- **Tokens:** enforced only if the provider can report usage. A task declaring
  `max_tokens` is rejected at creation while usage reporting is unsupported
  (existing decision, unchanged). A reservation reserves the *declared maximum*,
  never an estimate.
- **Duration:** the runtime can measure elapsed wall time itself, so duration is
  enforceable in 6.1C for the `worker` source, and conservatively bounded by the
  timeout for `recovery_bound`.
- They are not interchangeable: a provider may be slow without consuming tokens,
  and may consume tokens quickly. Both are tracked, neither is derived from the
  other.
- **Cost/money:** not in scope. The existing `TaskBudget` sketch mentions a cost
  limit; without a price table it would be a fabricated number.

---

## 7. Crash matrix — every accounting boundary

| # | Crash point | Durable state | Recovery action |
|---|---|---|---|
| 1 | before the reservation | `Pending`, no ledger row | nothing charged; `Pending` → `RetryReady` |
| 2 | after reserve, before dispatch | `Pending` + reservation | release the reservation — dispatch provably never happened |
| 3 | after dispatch, before settlement | `Dispatched` + reservation | retain; `OutcomeUnknown` |
| 4 | after settlement, before the checkpoint | settlement + `Dispatched` | settlement exists; classify `OutcomeUnknown` but **do not** retain the reservation again |
| 5 | during reconciliation adjustment | adjustment + `OutcomeUnknown` | adjustment stands; checkpoint stays until a verdict exists |
| 6 | after checkpoint success, before any release | settlement + `Succeeded` | release is implicit in settlement; nothing to do |

Row 4 is the mirror image of the review's gap, and it is why exposure is
supersession: a settlement that outran the checkpoint must not be charged twice
by a recovery pass that sees only the checkpoint.

---

## 8. Concurrency tests required before acceptance

1. **Parent oversubscription:** N threads create children against a parent whose
   remaining envelope fits only one. Exactly one succeeds; the rest get
   `ParentBudgetExceeded`. (Requires `BEGIN IMMEDIATE`.)
2. **Concurrent reserve for the same invocation:** two threads reserve the same
   `(task, invocation)`; exactly one row exists.
3. **Concurrent settle:** two settlements for the same invocation; exactly one
   row, identical amount.
4. **Reserve/settle interleaving:** settle racing a recovery pass that is
   classifying the same invocation; exposure is computed once.
5. **Release under an unresolved sibling:** a child completing does not release
   budget held by a sibling with an `OutcomeUnknown` invocation.

---

## 9. Decisions requested

| # | Decision | Recommendation |
|---|---|---|
| 1 | Drop the `Release` entry kind and model release as settlement supersession (§3.1) | yes — removes a crash window and a redundant row |
| 2 | Partial unique indexes instead of `UNIQUE(invocation_id, entry_kind)` | yes — adjustments must repeat |
| 3 | Elapsed captured at recovery classification with `recovery_bound` | yes — otherwise blocked time is billed as execution time |
| 4 | Derived child allocations rather than a stored counter | yes — one source of truth |
| 5 | `BEGIN IMMEDIATE` for every reservation transaction | required |
| 6 | Money/cost budget | defer until a price source exists |

Once these are settled I can implement `kernel/src/delegation/budget.rs` plus
migration M9 and the concurrency suite. Until then no budget code exists.
