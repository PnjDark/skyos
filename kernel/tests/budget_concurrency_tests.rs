/// Phase 6.1C — concurrency acceptance gates.
///
/// The transactional `UPDATE` / `INSERT` is only a foundation; these tests run
/// real competing threads against one SQLite file and require that the budgets
/// never oversubscribe and never double-record.
use std::sync::{Arc, Barrier};
use std::thread;

use kernel::delegation::{
    BudgetKernel, ChildTaskSpec, DelegationKernel, ElapsedSource, EntryKind, Envelope,
};
use kernel::events::EventBus;
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use uuid::Uuid;

struct Rig {
    _dir: tempfile::TempDir,
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
            task_store,
            event_bus,
        }
    }

    fn budget(&self) -> Arc<BudgetKernel> {
        Arc::new(BudgetKernel::open(self.task_store.clone()).unwrap())
    }

    fn delegation(&self) -> Arc<DelegationKernel> {
        Arc::new(DelegationKernel::open(self.task_store.clone(), self.event_bus.clone()).unwrap())
    }

    fn running_task(&self, title: &str) -> Uuid {
        let task_id = self
            .task_store
            .create_task(title, TaskState::Ready, 0)
            .unwrap();
        self.task_store
            .transition_state(task_id, TaskState::Ready, TaskState::Claimed)
            .unwrap();
        self.task_store
            .transition_state(task_id, TaskState::Claimed, TaskState::Running)
            .unwrap();
        task_id
    }

    fn budgeted_task(&self, budget: &BudgetKernel, tokens: i64) -> Uuid {
        let task_id = self.running_task("budgeted");
        budget
            .declare_budget(
                task_id,
                Envelope {
                    max_tokens: Some(tokens),
                    max_elapsed_ms: Some(60_000),
                },
            )
            .unwrap();
        task_id
    }
}

// ── 1. Parent oversubscription ──────────────────────────────────────────────

#[test]
fn concurrent_child_allocations_cannot_oversubscribe_the_parent() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = rig.budgeted_task(&budget, 1_000);

    const THREADS: usize = 8;
    const ALLOCATION: i64 = 600; // only one can fit in 1,000

    let barrier = Arc::new(Barrier::new(THREADS));
    let succeeded = thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|index| {
                let delegation = Arc::clone(&delegation);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    delegation
                        .create_child_with_budget(
                            parent,
                            ChildTaskSpec::new(format!("child-{index}"), "work"),
                            ALLOCATION,
                        )
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|succeeded| *succeeded)
            .count()
    });

    assert_eq!(
        succeeded, 1,
        "exactly one allocation may fit the parent's envelope"
    );
    assert_eq!(
        budget.available_tokens(parent).unwrap().unwrap(),
        400,
        "the parent must be charged exactly once"
    );
    assert_eq!(delegation.children(parent).unwrap().len(), 1);
}

// ── 2. Concurrent reservations for one invocation ───────────────────────────

#[test]
fn concurrent_reservations_for_one_invocation_yield_one_row() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = rig.budgeted_task(&budget, 1_000);
    let invocation = Uuid::new_v4();

    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    thread::scope(|scope| {
        for _ in 0..THREADS {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                budget
                    .reserve(task, invocation, 250, 5_000, "runtime", "pre-dispatch")
                    .expect("an identical reservation is idempotent, not a conflict");
            });
        }
    });

    let entries = budget.entries_for_invocation(invocation).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Reservation)
            .count(),
        1,
        "concurrent reservations must collapse to one row"
    );
    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        250
    );
}

// ── 3. Concurrent settlements ───────────────────────────────────────────────

#[test]
fn concurrent_settlements_yield_one_row() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = rig.budgeted_task(&budget, 1_000);
    let invocation = Uuid::new_v4();
    budget
        .reserve(task, invocation, 400, 5_000, "runtime", "pre-dispatch")
        .unwrap();

    const THREADS: usize = 6;
    let barrier = Arc::new(Barrier::new(THREADS));
    thread::scope(|scope| {
        for _ in 0..THREADS {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
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
                    .expect("an identical settlement is idempotent");
            });
        }
    });

    let entries = budget.entries_for_invocation(invocation).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Settlement)
            .count(),
        1
    );
    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        120,
        "settlement supersedes the reservation exactly once"
    );
}

// ── 4. Settlement racing an exposure read ───────────────────────────────────

#[test]
fn settlement_racing_an_exposure_read_is_counted_once() {
    let rig = Rig::new();
    let budget = rig.budget();
    let task = rig.budgeted_task(&budget, 1_000);
    let invocation = Uuid::new_v4();
    budget
        .reserve(task, invocation, 500, 5_000, "runtime", "pre-dispatch")
        .unwrap();

    let barrier = Arc::new(Barrier::new(8));
    thread::scope(|scope| {
        for _ in 0..4 {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                // Readers may see the reservation or the settlement, but
                // never a partial state and never a sum.
                let exposure = budget.exposure_of_invocation(invocation).unwrap().unwrap();
                assert!(
                    exposure.tokens == 500 || exposure.tokens == 150,
                    "exposure must be either the reservation or the settlement, got {}",
                    exposure.tokens
                );
            });
        }
        for _ in 0..4 {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                let _ = budget.settle(
                    task,
                    invocation,
                    150,
                    800,
                    ElapsedSource::Worker,
                    "runtime",
                    "measured",
                );
            });
        }
    });

    assert_eq!(
        budget
            .exposure_of_invocation(invocation)
            .unwrap()
            .unwrap()
            .tokens,
        150
    );
}

// ── 5. An unresolved sibling holds budget ───────────────────────────────────

#[test]
fn an_unresolved_sibling_holds_budget_against_release() {
    let rig = Rig::new();
    let budget = rig.budget();
    let delegation = rig.delegation();
    let parent = rig.budgeted_task(&budget, 1_000);

    let finished = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("finished", "work"), 400)
        .unwrap();
    let uncertain = delegation
        .create_child_with_budget(parent, ChildTaskSpec::new("uncertain", "work"), 400)
        .unwrap();

    for child in [finished, uncertain] {
        rig.task_store
            .transition_state(child, TaskState::Created, TaskState::Ready)
            .ok();
        rig.task_store
            .transition_state(child, TaskState::Ready, TaskState::Claimed)
            .unwrap();
        rig.task_store
            .transition_state(child, TaskState::Claimed, TaskState::Running)
            .unwrap();
    }

    // `finished` settles 100 of its 400 and completes.
    let done_invocation = Uuid::new_v4();
    budget
        .reserve(finished, done_invocation, 100, 1_000, "runtime", "step")
        .unwrap();
    budget
        .settle(
            finished,
            done_invocation,
            100,
            400,
            ElapsedSource::Worker,
            "runtime",
            "measured",
        )
        .unwrap();
    delegation.complete_task(finished).unwrap();

    // `uncertain` reserved but never settled.
    budget
        .reserve(uncertain, Uuid::new_v4(), 120, 1_000, "runtime", "step")
        .unwrap();
    delegation.complete_task(uncertain).unwrap();

    // 100 settled (finished) + 400 held (uncertain allocation) = 500 committed.
    assert_eq!(budget.available_tokens(parent).unwrap().unwrap(), 500);

    // A concurrent attempt to take more than remains must fail.
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let delegation = Arc::clone(&delegation);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    delegation
                        .create_child_with_budget(
                            parent,
                            ChildTaskSpec::new(format!("late-{index}"), "work"),
                            300,
                        )
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "only one 300-token allocation fits the remaining 500"
    );
}
