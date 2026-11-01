/// Phase 6.1C — budget ledger, exposure and the crash matrix.
///
/// The accounting rule under test: a reservation protects budget *before*
/// execution, a settlement records measured usage *after* it, and exposure is
/// supersession — `adjustments + COALESCE(settlement, reservation)` — never a
/// sum of both.
use std::path::PathBuf;

use kernel::delegation::{
    BudgetError, BudgetKernel, ChildTaskSpec, DelegationKernel, ElapsedSource, Envelope,
};
use kernel::events::EventBus;
use kernel::tasks::checkpoint::{
    CheckpointInvocation, CheckpointStore, SideEffectSemantics, compute_argument_fingerprint,
    compute_idempotency_key,
};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use uuid::Uuid;

struct Rig {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    task_store: TaskStore,
    event_bus: EventBus,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("runtime_state.db");
        let task_store = TaskStore::open(&db_path).unwrap();
        let event_bus = EventBus::open(&db_path).unwrap();
        Self {
            _dir: dir,
            db_path,
            task_store,
            event_bus,
        }
    }

    fn budget(&self) -> BudgetKernel {
        BudgetKernel::open(self.task_store.clone()).unwrap()
    }

    fn delegation(&self) -> DelegationKernel {
        DelegationKernel::open(self.task_store.clone(), self.event_bus.clone()).unwrap()
    }

    fn running_task(&self, title: &str) -> Uuid {
        let task_id = self
            .task_store
            .create_task(title, TaskState::Ready, 0)
            .unwrap();
        self.start(task_id);
        task_id
    }

    fn start(&self, task_id: Uuid) {
        if self.state(task_id) == TaskState::Created {
            self.task_store
                .transition_state(task_id, TaskState::Created, TaskState::Ready)
                .unwrap();
        }
        if self.state(task_id) == TaskState::Ready {
            self.task_store
                .transition_state(task_id, TaskState::Ready, TaskState::Claimed)
                .unwrap();
        }
        self.task_store
            .transition_state(task_id, TaskState::Claimed, TaskState::Running)
            .unwrap();
    }

    fn state(&self, task_id: Uuid) -> TaskState {
        self.task_store.get_task(&task_id).unwrap().unwrap().state
    }
}

/// A running task with a 1,000-token envelope.
fn budgeted_task(rig: &Rig, budget: &BudgetKernel) -> Uuid {
    let task_id = rig.running_task("budgeted");
    budget
        .declare_budget(
            task_id,
            Envelope {
                max_tokens: Some(1_000),
                max_elapsed_ms: Some(60_000),
            },
        )
        .unwrap();
    task_id
}

// ── Exposure semantics ──────────────────────────────────────────────────────

#[test]
fn a_settlement_supersedes_its_reservation() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 400, 30_000, "runtime", "pre-dispatch")
        .unwrap();
    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        400
    );

    budget
        .settle(
            task,
            invocation,
            120,
            900,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        120,
        "settlement replaces the reservation; it must not be added to it"
    );
    assert_eq!(budget.exposure_of_task(task).unwrap().tokens, 120);
}

#[test]
fn adjustments_are_signed_and_added_once() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 300, 10_000, "runtime", "pre-dispatch")
        .unwrap();
    budget
        .settle(
            task,
            invocation,
            100,
            500,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    budget
        .adjust(
            task,
            invocation,
            50,
            0,
            "operator",
            "provider reported extra usage",
            "adj-1",
        )
        .unwrap();
    budget
        .adjust(task, invocation, -20, 0, "operator", "refund", "adj-2")
        .unwrap();

    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        130,
        "adjustments are signed deltas applied on top of the settlement"
    );
    assert_eq!(
        budget.entries_for_invocation(invocation).unwrap().len(),
        4,
        "adjustments append; they never replace"
    );
}

#[test]
fn repeating_the_same_adjustment_is_idempotent_but_a_conflict_is_refused() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 100, 1_000, "runtime", "pre-dispatch")
        .unwrap();

    budget
        .adjust(task, invocation, 10, 0, "operator", "extra", "same-key")
        .unwrap();
    budget
        .adjust(task, invocation, 10, 0, "operator", "extra", "same-key")
        .unwrap();

    let error = budget
        .adjust(task, invocation, 99, 0, "operator", "different", "same-key")
        .unwrap_err();
    assert!(matches!(error, BudgetError::AdjustmentConflict(key) if key == "same-key"));

    assert_eq!(
        budget.entries_for_invocation(invocation).unwrap().len(),
        2,
        "one reservation plus exactly one adjustment"
    );
}

#[test]
fn a_repeated_reservation_is_idempotent_and_a_conflict_is_refused() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    let first = budget
        .reserve(task, invocation, 250, 5_000, "runtime", "pre-dispatch")
        .unwrap();
    let again = budget
        .reserve(task, invocation, 250, 5_000, "runtime", "pre-dispatch")
        .unwrap();
    assert_eq!(first.entry_id, again.entry_id);

    let error = budget
        .reserve(task, invocation, 900, 5_000, "runtime", "changed my mind")
        .unwrap_err();
    assert!(matches!(error, BudgetError::Conflict { .. }));
}

#[test]
fn a_reservation_beyond_the_envelope_is_refused() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    let error = budget
        .reserve(task, invocation, 1_500, 1_000, "runtime", "too much")
        .unwrap_err();
    assert!(matches!(
        error,
        BudgetError::BudgetExceeded {
            requested: 1_500,
            available: 1_000,
            ..
        }
    ));
    assert!(budget.exposure_of_invocation(invocation).unwrap().is_none());
}

#[test]
fn a_reservation_without_a_declared_envelope_is_refused() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = rig.running_task("unbudgeted");

    let error = budget
        .reserve(task, Uuid::new_v4(), 10, 1_000, "runtime", "no envelope")
        .unwrap_err();
    assert!(matches!(error, BudgetError::BudgetNotDeclared(id) if id == task));
}

// ── Crash matrix ────────────────────────────────────────────────────────────

#[test]
fn crash_before_reservation_charges_nothing() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    assert!(budget.exposure_of_invocation(invocation).unwrap().is_none());
    assert_eq!(budget.exposure_of_task(task).unwrap().tokens, 0);
}

#[test]
fn crash_after_reservation_before_dispatch_releases_it() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 500, 20_000, "runtime", "pre-dispatch")
        .unwrap();

    // Recovery observes a `Pending` checkpoint: dispatch provably never
    // happened, so the reservation is settled at zero rather than deleted.
    budget
        .settle_never_dispatched(task, invocation, "recovery")
        .unwrap();

    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        0,
        "a provably-undispatched operation must not consume budget"
    );
    assert_eq!(
        budget.entries_for_invocation(invocation).unwrap().len(),
        2,
        "append-only: the reservation is preserved, the zero settlement supersedes it"
    );
}

#[test]
fn crash_after_dispatch_retains_the_reservation() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 700, 25_000, "runtime", "pre-dispatch")
        .unwrap();

    // The worker died after dispatch. Recovery writes nothing; the reservation
    // stands. An unknown operation is never free.
    let exposure = budget.exposure_of_invocation(invocation).unwrap().unwrap();
    assert_eq!(exposure.tokens, 700);
    assert_eq!(
        exposure.duration_ms, 25_000,
        "duration is conservatively held at the dispatch timeout"
    );
}

#[test]
fn crash_after_settlement_before_the_checkpoint_does_not_double_count() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 600, 10_000, "runtime", "pre-dispatch")
        .unwrap();
    budget
        .settle(
            task,
            invocation,
            240,
            2_000,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    // The checkpoint never reached `Succeeded`; a recovery pass would see a
    // dispatched invocation. The settlement must win, exactly once.
    assert_eq!(
        budget.exposure_of_task(task).unwrap().tokens,
        240,
        "settlement + reservation would charge the same work twice"
    );
}

#[test]
fn crash_after_checkpoint_success_is_stable() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    budget
        .reserve(task, invocation, 400, 8_000, "runtime", "pre-dispatch")
        .unwrap();
    budget
        .settle(
            task,
            invocation,
            133,
            1_500,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    for _ in 0..3 {
        assert_eq!(budget.exposure_of_task(task).unwrap().tokens, 133);
    }
}

// ── Parent / child envelopes ────────────────────────────────────────────────

#[test]
fn a_child_allocation_is_drawn_from_the_parent() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("child", "work"), 400)
        .unwrap();

    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        600,
        "the child's envelope occupies the parent immediately"
    );
}

#[test]
fn a_child_allocation_beyond_the_parent_is_refused_without_partial_writes() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    let error = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("too big", "work"), 1_001)
        .unwrap_err();
    assert!(matches!(
        error,
        BudgetError::ParentBudgetExceeded {
            requested: 1_001,
            available: 1_000,
            ..
        }
    ));

    assert!(
        delegation.children(parent).unwrap().is_empty(),
        "the child row must not survive a rejected allocation"
    );
    assert_eq!(budget.available_tokens(parent).unwrap().unwrap(), 1_000);
}

#[test]
fn an_active_child_holds_its_allocation_not_its_usage() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    let child = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("child", "work"), 400)
        .unwrap();
    rig.start(child);

    // The child spends a little of its own envelope.
    let child_invocation = Uuid::new_v4();
    budget
        .reserve(child, child_invocation, 50, 1_000, "runtime", "child step")
        .unwrap();
    budget
        .settle(
            child,
            child_invocation,
            50,
            200,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        600,
        "the parent commits the child's allocation, not allocation plus usage"
    );
    assert_eq!(budget.available_tokens(child).unwrap().unwrap(), 350);
}

#[test]
fn a_terminal_resolved_child_releases_its_unused_allocation() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    let child = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("child", "work"), 400)
        .unwrap();
    rig.start(child);

    let invocation = Uuid::new_v4();
    budget
        .reserve(child, invocation, 100, 1_000, "runtime", "child step")
        .unwrap();
    budget
        .settle(
            child,
            invocation,
            50,
            400,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    delegation.complete_task(child).unwrap();

    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        950,
        "only the 50 tokens actually used stay charged; 350 returns to the parent"
    );
}

#[test]
fn an_unresolved_child_keeps_its_allocation_held_even_when_terminal() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    let child = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("child", "work"), 400)
        .unwrap();
    rig.start(child);

    // Reserved, never settled: usage is unknown.
    let invocation = Uuid::new_v4();
    budget
        .reserve(child, invocation, 100, 1_000, "runtime", "uncertain step")
        .unwrap();

    delegation.complete_task(child).unwrap();

    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        600,
        "a terminal child with unresolved usage must not release its envelope"
    );
}

#[test]
fn nested_delegation_rolls_up_without_double_counting() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = budgeted_task(&rig, &budget);

    let child = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("child", "work"), 400)
        .unwrap();

    let grandchild = delegation
        .create_child_with_budget(child, ChildTaskSpec::new("grandchild", "work"), 100)
        .unwrap();
    rig.start(grandchild);

    // The grandchild spends 30 of its 100.
    let invocation = Uuid::new_v4();
    budget
        .reserve(grandchild, invocation, 30, 1_000, "runtime", "step")
        .unwrap();
    budget
        .settle(
            grandchild,
            invocation,
            30,
            100,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();

    // Parent: commits the child's 400 allocation, not 400 + 100.
    assert_eq!(budget.available_tokens(parent).unwrap().unwrap(), 600);
    // Child: commits the grandchild's 100 allocation.
    assert_eq!(budget.available_tokens(child).unwrap().unwrap(), 300);

    delegation.complete_task(grandchild).unwrap();
    assert_eq!(
        budget.available_tokens(child).unwrap().unwrap(),
        370,
        "the grandchild's unused 70 returns to the child, not to the grandparent"
    );
    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        600,
        "an ancestor's commitment is unchanged by a descendant's settlement"
    );
}

// ── Recovery-bound duration ─────────────────────────────────────────────────

#[test]
fn recovery_bound_is_capped_by_the_durable_dispatch_timeout() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = budgeted_task(&rig, &budget);
    let invocation = Uuid::new_v4();

    // A dispatched checkpoint whose timestamp is an hour old.
    let checkpoints = CheckpointStore::open(&rig.db_path).unwrap();
    let connection = checkpoints.connection().unwrap();
    let arguments = serde_json::json!({ "message": "x" });
    let key = compute_idempotency_key(&task, 0, "git", "commit", &arguments);
    CheckpointStore::write_pending_invocation(
        &connection,
        task,
        "agent",
        0,
        &CheckpointInvocation {
            invocation_id: invocation,
            idempotency_key: key.clone(),
            argument_fingerprint: compute_argument_fingerprint(&arguments),
            semantics: SideEffectSemantics::Reconcilable,
            tool_id: "git".into(),
            operation_id: "commit".into(),
        },
    )
    .unwrap();
    CheckpointStore::mark_dispatched(&connection, task, 0, invocation, &key, "git", "commit")
        .unwrap();
    let an_hour_ago = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    connection
        .execute(
            "UPDATE task_checkpoints SET checkpoint_time = ?1 WHERE task_id = ?2 AND step_number = 0",
            rusqlite::params![an_hour_ago, task.to_string()],
        )
        .unwrap();
    drop(connection);

    budget
        .reserve(
            task,
            invocation,
            100,
            30_000,
            "runtime",
            "dispatch timeout 30s",
        )
        .unwrap();

    let bound = budget.recovery_bound(invocation).unwrap().unwrap();
    assert_eq!(bound.dispatched_at, an_hour_ago);
    assert_eq!(bound.timeout_ms, Some(30_000));
    assert_eq!(
        bound.elapsed_ms, 30_000,
        "an hour of blocked time is capped at the dispatch timeout, not billed as execution"
    );
    assert!(bound.capped);
}

#[test]
fn recovery_bound_is_absent_for_an_invocation_that_never_dispatched() {
    let rig = Rig::new();
    let budget = rig.budget();
    assert!(budget.recovery_bound(Uuid::new_v4()).unwrap().is_none());
}
