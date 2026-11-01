# Phase 6.1D — Cancellation State Machine & Transaction Boundaries

**Status:** design proposal for sign-off. **No cancellation code has been written.**
**Baseline:** Phase 6.1C locked at 309 tests; this document changes nothing in it.

The central problem, stated once: *a parent can request cancellation of its
descendants, but it cannot declare them cancelled because it sent a request.*
Intent and completion are different events, owned by different transactions, and
the terminal state must be the last thing that happens — not the first.

---

## 1. Ground truth — what the code actually has

| Assumption in the draft | Reality |
|---|---|
| "Keep the existing `Cancelled` task state" | **There is no `Cancelled` state.** `TaskState` has 9 variants: `Created, Ready, Claimed, Running, Waiting, Blocked, Escalated, Failed, Completed` |
| `Validating` is an active state to cancel | **`Validating` does not exist** — it is Phase 6.1E |
| "Signal workers and confirm termination" | **There is no worker supervisor.** No process registry, no PID tracking, no heartbeat. `ExecutorAgent::run` is an in-process loop |
| "Cancel the parent task's process" | The runtime has no handle on any process |

Current transition matrix (`kernel/src/tasks/state.rs`), verbatim:

```
Created → Ready | Blocked
Ready → Claimed
Claimed → Running | Blocked
Running → Waiting | Blocked | Failed | Completed
Waiting → Running | Blocked
Blocked → Ready | Escalated
Escalated → Ready | Failed
Failed → Ready
```

`Completed`, `Failed` are terminal in practice (`Failed → Ready` exists for retry).

---

## 2. Corrections to the draft

### C1. Boundary A is self-defeating

The draft's Boundary A commits, in one transaction: persist intent **and**
"transition task state to `TaskState::Cancelled`". That makes the task terminal
before a single descendant has been enumerated — contradicting invariant 3 in the
same document ("a parent cannot become terminally cancelled while descendants
remain active").

Terminal cancellation must be the **last** transaction of the cascade, not the
first. Boundary A should move the task to a *non-terminal* `Cancelling` state.

### C2. Two states must be added, not one

`Cancelled` (terminal) and `Cancelling` (non-terminal). Without `Cancelling`
there is nowhere to park a task between "someone asked" and "everything is
confirmed stopped", and the runtime cannot tell a cancelling task from a running
one — so the executor would keep taking steps.

### C3. There is no worker supervisor to build

Boundary C says "active process workers are sent SIGTERM / TerminateProcess".
Nothing in the runtime knows about worker processes. Building a supervisor now
means building a worker registry, a PID table and a heartbeat — and then
supervising zero processes, because the executor is in-process.

Recommendation: **cooperative cancellation for 6.1D**, with a durable
acknowledgement as the proof of inactivity. Process supervision lands in 6.3,
where worker processes actually exist and have PIDs to signal.

Cooperative form:

1. Coordinator persists intent and moves the task to `Cancelling`.
2. `ExecutorAgent` checks the task state at the top of every cycle (it already
   re-reads the grant there), and on `Cancelling` writes a
   `CancellationAcknowledged` record and exits with a new
   `AgentLoopStatus::Cancelled`.
3. The coordinator only commits `Cancelled` once every descendant has either
   acknowledged or is already terminal.

This satisfies invariant 4 exactly: a worker that never acknowledges leaves the
intent `AwaitingWorkers` and the task `Cancelling`. Nothing is assumed.

### C4. The intent needs an escalation path

Statuses in the draft are `Requested / Propagating / AwaitingWorkers / Completed`.
If a worker never acknowledges, the task is stuck in `AwaitingWorkers` forever
with no operator path. The existing `Escalated` state is the natural landing
place: after a deadline, intent → `Escalated`, task `Cancelling → Escalated`,
and a human owns it.

### C5. Boundary C.2 collides with Phase 5 recovery semantics — benignly, but it
must be a rule

The draft says dispatched invocations "transition to `OutcomeUnknown`". Phase 5's
`recover_one` also marks a `Dispatched` checkpoint `OutcomeUnknown` **and**
transitions the task `Running → Blocked`. During cancellation the task is
`Cancelling`, and `transition_task_if_running` only fires when the state is
`Running` — so it already skips. That is luck, not design. Rule: the canceller
marks the *checkpoint* only; it never writes task state.

### C6. Budget release does not know about `Cancelled`

`child_committed` (`delegation/budget.rs`) treats only `"Completed" | "Failed"`
as terminal. A `Cancelled` child would hold its allocation forever — a leak. But
while `Cancelling`, the hold is exactly what we want. The rule has to be split:
`Cancelled` counts as terminal **only when it has no unresolved reservations**;
`Cancelling` never counts.

### C7. Idempotency of a repeated request

The draft's table has `task_id UNIQUE` but says a terminal task is rejected with
`TaskAlreadyTerminal`. A second request for a task that is already `Cancelling`
must return the existing intent, not fail — otherwise a retrying operator gets a
spurious error.

---

## 3. Proposed state machine

### 3.1 New variants

```rust
pub enum TaskState {
    Created, Ready, Claimed, Running, Waiting, Blocked,
    Cancelling,          // new: cancellation requested, not yet confirmed
    Escalated,
    Failed, Completed,
    Cancelled,           // new: terminal, reached only through Cancelling
}
```

### 3.2 Edges added

| From | To | Owner | Meaning |
|---|---|---|---|
| Created, Ready, Claimed, Running, Waiting, Blocked, Escalated | `Cancelling` | cancellation coordinator | intent durable; no new work starts |
| `Cancelling` | `Cancelled` | coordinator, once every descendant is terminal **and** every live descendant acknowledged | terminal |
| `Cancelling` | `Escalated` | coordinator, deadline exceeded | a worker did not confirm |

### 3.3 Edges deliberately **not** added

| Edge | Why not |
|---|---|
| `* → Cancelled` directly | terminal cancellation without a cascade is exactly the assumption this phase exists to prevent |
| `Cancelling → Completed` | a cancellation that lands first wins; completion is refused |
| `Completed/Failed → Cancelling` | invariant 7: a finished task's state and artifacts are preserved |
| `Cancelled → *` | terminal |

Note the interaction with dependency release: a `Cancelling` prerequisite is not
`Completed`, so its dependents stay `Created`. That is the desired behaviour —
cancellation never releases downstream work.

### 3.4 The completion race, decided

"Race cancellation against task completion" has exactly one deterministic answer,
because both paths check the state inside an `IMMEDIATE` transaction:

* completion commits first → task is `Completed`; the cancellation request is
  refused as already-terminal;
* cancellation commits first → task is `Cancelling`; `complete_task` refuses.

There is no third outcome and no "last writer wins".

---

## 4. Intent record

Extended beyond the draft (additions marked):

```sql
CREATE TABLE IF NOT EXISTS task_cancellation_intents (
    intent_id             TEXT PRIMARY KEY,
    task_id               TEXT NOT NULL UNIQUE,
    root_task_id          TEXT NOT NULL,          -- + the cascade this belongs to
    requested_by_actor    TEXT NOT NULL,
    auth_method           TEXT NOT NULL,          -- + Phase 6.0 identity provenance
    cancellation_reason   TEXT NOT NULL,
    requested_at          TEXT NOT NULL,
    acknowledge_deadline  TEXT NOT NULL,          -- + when to escalate
    status                TEXT NOT NULL
                          CHECK (status IN ('Requested','Propagating',
                                            'AwaitingWorkers','Escalated','Completed')),
    acknowledged_at       TEXT,                   -- + proof of worker inactivity
    escalated_at          TEXT,
    completed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_cancellation_root
    ON task_cancellation_intents(root_task_id);
```

`root_task_id` is what makes resume cheap: one query finds every node of a
cascade in flight.

`acknowledged_at` is the only evidence the runtime accepts for "the worker is
gone". It is written by the executor, not by the coordinator.

---

## 5. Transaction boundaries

Every row below is one `BEGIN IMMEDIATE` transaction. Nothing spans two.

| # | Operation | Inside the transaction | Crash before commit | Crash after commit |
|---|---|---|---|---|
| A | **Request** | validate task is non-terminal; `INSERT` intent (`Requested`); task → `Cancelling`; emit `CancellationRequested` | nothing happened | intent durable, task visibly cancelling |
| B | **Enumerate** | read-only recursive CTE over `parent_task_id` | — | — |
| C | **Mark one descendant** | `INSERT` intent for that node (`Propagating`); node → `Cancelling`; emit event; parent intent → `Propagating` | node unmarked; resume re-enumerates (UNIQUE `task_id` makes it idempotent) | node marked |
| D | **Await** | parent intent → `AwaitingWorkers` once no `Requested`/`Propagating` nodes remain | — | waiting state durable |
| E | **Acknowledge** | `acknowledged_at` set by the executor | worker did not stop: stays waiting | acknowledgement durable |
| F | **Terminal, per node** | all descendants terminal + this node acknowledged → node `Cancelling → Cancelled`; intent → `Completed`; emit | node not terminal; resume repeats (idempotent) | terminal |
| G | **Escalate** | deadline exceeded → node `Cancelling → Escalated`; intent → `Escalated`; emit | — | operator owns it |

Deliberate choice: **one transaction per node, not one for the whole subtree.**
A single transaction over a deep tree holds the write lock for the entire
cascade and cannot make partial progress visible; per-node transactions are
resumable and the intent status makes progress legible.

### 5.1 The child-creation race

`create_child_inner` already opens `IMMEDIATE`. Adding two checks closes the
escape window:

```sql
-- inside the same transaction that inserts the child row
SELECT 1 FROM task_cancellation_intents WHERE task_id = ?parent;      -- intent exists → reject
SELECT state FROM tasks WHERE task_id = ?parent;                       -- state = 'Cancelling' → reject
```

Serialization gives both orderings a correct outcome:

* child commits first → the child exists before enumeration, so the cascade
  includes it;
* intent commits first → creation sees the intent and is refused.

Two independent checks are deliberate: the intent row is the durable record, the
state is the fast path. Neither alone is sufficient if a future code path writes
one without the other.

---

## 6. Crash matrix

| # | Crash point | Durable state | Resume action |
|---|---|---|---|
| 1 | after A, before any node marked | root `Cancelling`, intent `Requested` | re-enumerate from `root_task_id`, continue at C |
| 2 | mid-cascade | some nodes `Cancelling` | re-enumerate; already-marked nodes are no-ops |
| 3 | after all marked, before terminal | all nodes `Cancelling`, intents `AwaitingWorkers` | check acknowledgements; terminal those satisfied |
| 4 | after one child terminal, before the parent | child `Cancelled`, parent `Cancelling` | parent proceeds when its own conditions hold |
| 5 | worker never acknowledges | intent `AwaitingWorkers` | after deadline → G |
| 6 | coordinator killed between checkpoint `OutcomeUnknown` and node terminal | checkpoint `OutcomeUnknown`, node `Cancelling` | F repeats; checkpoint write is idempotent |
| 7 | concurrent child creation | either the child exists (and is cascaded) or the request was refused | — |

---

## 7. Invariant → mechanism

| # | Invariant | Mechanism |
|---|---|---|
| 1 | Persist intent before signal | there is no signal in 6.1D; intent + `Cancelling` commit before anything can observe the task |
| 2 | Idempotent, resumable | `UNIQUE(task_id)`; monotonic status; resume re-derives from `root_task_id` |
| 3 | Parent not terminal while descendants active | `Cancelling → Cancelled` is gated on the subtree; `Cancelling → Completed` does not exist |
| 4 | Ignoring worker stays unresolved | only `acknowledged_at` unlocks terminal; otherwise `Escalated` |
| 5 | `OutcomeUnknown` retains budget | no settlement is written; `child_committed` holds while unresolved |
| 6 | Effect not assumed reversed | the canceller writes `OutcomeUnknown` to the checkpoint and never `Succeeded`/`Failed` |
| 7 | Completed work preserved | no edge from terminal states; enumeration skips terminal nodes |

---

## 8. State-transition audit — every site that changes

| File | Change | Risk |
|---|---|---|
| `kernel/src/tasks/state.rs` | 2 enum variants, `as_str`, `TryFrom`, 9 new edges, Display | every exhaustive `match` must compile-fail first |
| `kernel/src/delegation/budget.rs:313` | `child_committed` terminal set → `Completed \| Failed \| (Cancelled if resolved)` | silent budget leak if missed |
| `kernel/src/delegation/store.rs:182` | `complete_task` refuses `Cancelling` | completion race |
| `kernel/src/delegation/store.rs:56` | `create_child_inner` rejects cancelling parents | escape race |
| `kernel/src/recovery/mod.rs` | no code change; add a test that a `Cancelling` task is not moved to `Blocked` | recovery/cancellation interference |
| `agents/src/executor.rs` | per-cycle state check + acknowledgement + `AgentLoopStatus::Cancelled` | loop must stop between steps, never mid-tool |
| `clients/cli` | `sky task cancel <id> --reason` | operator surface |

The enum change is a compile-time net: `as_str`, `TryFrom` and any exhaustive
match will fail to build until every site is updated.

---

## 9. Acceptance tests (mapped to the ruling)

| Test | Invariant |
|---|---|
| cancel a parent with three levels of descendants | 2, 3 |
| kill the coordinator after intent, restart, resume | 2 |
| kill a worker mid-execution; node stays `Cancelling` until acknowledged | 4 |
| cancel with an `OutcomeUnknown` invocation; reservation still held | 5 |
| repeat the same request; no duplicate transitions, same intent | 2, 7 |
| race cancellation against completion | §3.4 |
| race cancellation against child creation | §5.1 |
| completed descendant keeps state and artifacts | 7 |
| dispatched checkpoint becomes `OutcomeUnknown`, task state untouched | 5, 6 |
| deadline exceeded → `Escalated`, never `Cancelled` | 4 |

---

## 10. Decisions requested before implementation

| # | Decision | Recommendation |
|---|---|---|
| 1 | Cooperative cancellation now, process supervision in 6.3 | yes — there are no worker processes to supervise |
| 2 | Add both `Cancelling` and `Cancelled` | yes — one state cannot express intent and completion |
| 3 | Acknowledgement deadline | 60 s default, configurable, escalation to `Escalated` |
| 4 | Cascade scope | all non-terminal descendants; terminal nodes untouched |
| 5 | Budget release on `Cancelled` | immediately once resolved — a cancelled task with no unresolved invocations is settled |
| 6 | Does cancelling a child mark its dependents blocked? | no: they stay `Created`, because a cancelled prerequisite never completes |

Until these are settled, no cancellation code exists.
