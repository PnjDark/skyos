/// Phase 6.1A/6.1B — durable delegation DAG and readiness gate.
///
/// The first milestone: a parent with two dependent children, blocked until
/// their prerequisites complete, surviving a process restart, and rejecting
/// cycles without leaving partial writes.
use std::path::PathBuf;

use kernel::delegation::{ChildTaskSpec, DelegationError, DelegationKernel};
use kernel::events::EventBus;
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

    fn kernel(&self) -> DelegationKernel {
        DelegationKernel::open(self.task_store.clone(), self.event_bus.clone()).unwrap()
    }

    /// A parent task, already running.
    fn running_parent(&self) -> Uuid {
        self.running_task("parent")
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

    fn state(&self, task_id: Uuid) -> TaskState {
        self.task_store.get_task(&task_id).unwrap().unwrap().state
    }

    /// Drive a child through `Created → Ready → Claimed → Running`.
    ///
    /// Tolerates a task that the readiness gate already promoted to `Ready`.
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

    /// Rebuild every runtime object against the same database file.
    fn reopen(&self) -> (TaskStore, DelegationKernel) {
        let task_store = TaskStore::open(&self.db_path).unwrap();
        let event_bus = EventBus::open(&self.db_path).unwrap();
        let kernel = DelegationKernel::open(task_store.clone(), event_bus).unwrap();
        (task_store, kernel)
    }
}

// ── 1. Parent-child creation ─────────────────────────────────────────────────

#[test]
fn child_tasks_are_created_under_their_parent() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let first = kernel
        .create_child(parent, ChildTaskSpec::new("research", "gather sources"))
        .unwrap();
    let second = kernel
        .create_child(parent, ChildTaskSpec::new("write", "draft the report"))
        .unwrap();

    let children = kernel.children(parent).unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(
        children
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>()
            .len(),
        2
    );
    assert!(children.iter().any(|task| task.task_id == first));
    assert!(children.iter().any(|task| task.task_id == second));

    // A child with no prerequisites is immediately eligible.
    assert_eq!(rig.state(first), TaskState::Ready);
    assert_eq!(rig.state(second), TaskState::Ready);
}

// ── 2. Prerequisite blocking ─────────────────────────────────────────────────

#[test]
fn a_dependent_child_stays_created_until_its_prerequisite_completes() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let first = kernel
        .create_child(parent, ChildTaskSpec::new("research", "gather sources"))
        .unwrap();
    // Starts Running so it is a realistic prerequisite.
    rig.start(first);
    let second = kernel
        .create_child(
            parent,
            ChildTaskSpec::new("write", "draft the report").depends_on(first),
        )
        .unwrap();

    assert_eq!(
        rig.state(second),
        TaskState::Created,
        "a dependent task must not be released while its prerequisite is running"
    );
    assert_eq!(
        kernel.dependencies_of(second).unwrap().len(),
        1,
        "the edge must be persisted, not merely implied"
    );
}

#[test]
fn an_edge_is_rejected_when_the_prerequisite_does_not_exist() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();
    let ghost = Uuid::new_v4();

    let error = kernel
        .create_child(
            parent,
            ChildTaskSpec::new("orphan", "depends on nothing real").depends_on(ghost),
        )
        .unwrap_err();

    assert!(matches!(error, DelegationError::DependencyNotFound(id) if id == ghost));
    assert!(
        kernel.children(parent).unwrap().is_empty(),
        "a rejected creation must not leave a partial child row"
    );
}

#[test]
fn a_task_cannot_depend_on_itself() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();
    let child = kernel
        .create_child(parent, ChildTaskSpec::new("loop", "self reference"))
        .unwrap();

    let error = kernel.add_dependency(child, child).unwrap_err();
    assert!(matches!(error, DelegationError::SelfDependency(id) if id == child));
}

// ── 3. Dependency release ────────────────────────────────────────────────────

#[test]
fn completing_a_prerequisite_releases_exactly_its_dependents() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let prerequisite = kernel
        .create_child(parent, ChildTaskSpec::new("research", "gather sources"))
        .unwrap();
    rig.start(prerequisite);

    let dependent = kernel
        .create_child(
            parent,
            ChildTaskSpec::new("write", "draft").depends_on(prerequisite),
        )
        .unwrap();
    // An unrelated task must not be affected by the release.
    let unrelated = kernel
        .create_child(parent, ChildTaskSpec::new("review", "independent"))
        .unwrap();
    rig.start(unrelated);

    let released = kernel.complete_task(prerequisite).unwrap();

    assert_eq!(
        released,
        vec![dependent],
        "exactly the eligible dependent must be released"
    );
    assert_eq!(rig.state(dependent), TaskState::Ready);
    assert_eq!(
        rig.state(unrelated),
        TaskState::Running,
        "unrelated tasks keep their state"
    );
}

#[test]
fn a_dependent_is_not_released_while_another_prerequisite_is_outstanding() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let first = kernel
        .create_child(parent, ChildTaskSpec::new("a", "first"))
        .unwrap();
    let second = kernel
        .create_child(parent, ChildTaskSpec::new("b", "second"))
        .unwrap();
    rig.start(first);
    rig.start(second);

    let dependent = kernel
        .create_child(
            parent,
            ChildTaskSpec::new("c", "needs both")
                .depends_on(first)
                .depends_on(second),
        )
        .unwrap();

    let released = kernel.complete_task(first).unwrap();
    assert!(
        released.is_empty(),
        "one of two prerequisites is not enough to release the dependent"
    );
    assert_eq!(rig.state(dependent), TaskState::Created);

    let released = kernel.complete_task(second).unwrap();
    assert_eq!(released, vec![dependent]);
    assert_eq!(rig.state(dependent), TaskState::Ready);
}

// ── 4. Cycle rejection ───────────────────────────────────────────────────────

#[test]
fn a_dependency_cycle_is_rejected_without_partial_writes() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let first = kernel
        .create_child(parent, ChildTaskSpec::new("first", "a"))
        .unwrap();
    let second = kernel
        .create_child(parent, ChildTaskSpec::new("second", "b").depends_on(first))
        .unwrap();

    let edges_before = kernel.all_dependencies().unwrap().len();

    // first -> second would close the loop second -> first -> second.
    let error = kernel.add_dependency(first, second).unwrap_err();
    assert!(
        matches!(
            error,
            DelegationError::CycleDetected {
                dependent,
                prerequisite
            } if dependent == first && prerequisite == second
        ),
        "unexpected error: {error:?}"
    );

    assert_eq!(
        kernel.all_dependencies().unwrap().len(),
        edges_before,
        "a rejected edge must not be written"
    );
    assert!(kernel.depends_transitively_on(second, first).unwrap());
    assert!(
        !kernel.depends_transitively_on(first, second).unwrap(),
        "the rejected edge must not exist in either direction"
    );
}

#[test]
fn a_deeper_cycle_is_rejected_too() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let a = kernel
        .create_child(parent, ChildTaskSpec::new("a", ""))
        .unwrap();
    let b = kernel
        .create_child(parent, ChildTaskSpec::new("b", "").depends_on(a))
        .unwrap();
    let c = kernel
        .create_child(parent, ChildTaskSpec::new("c", "").depends_on(b))
        .unwrap();

    // `a -> c` would close the loop, because c already depends on a through b.
    let error = kernel.add_dependency(a, c).unwrap_err();
    assert!(matches!(error, DelegationError::CycleDetected { .. }));
    assert!(
        !kernel.depends_transitively_on(a, c).unwrap(),
        "the rejected a -> c edge must not be introduced"
    );
    assert!(
        kernel.depends_transitively_on(c, a).unwrap(),
        "the pre-existing c -> b -> a chain must be untouched"
    );
}

// ── 5. Restart durability ────────────────────────────────────────────────────

#[test]
fn the_dag_and_readiness_survive_a_restart() {
    let rig = Rig::new();
    let parent = rig.running_parent();

    let (first, second) = {
        let kernel = rig.kernel();
        let first = kernel
            .create_child(parent, ChildTaskSpec::new("research", "sources"))
            .unwrap();
        rig.start(first);
        let second = kernel
            .create_child(
                parent,
                ChildTaskSpec::new("write", "draft").depends_on(first),
            )
            .unwrap();
        (first, second)
    };

    assert_eq!(rig.state(second), TaskState::Created);

    // Fresh runtime objects against the same file, as after a restart.
    let (task_store, kernel) = rig.reopen();

    assert_eq!(
        task_store.get_task(&second).unwrap().unwrap().state,
        TaskState::Created,
        "readiness must not be recomputed optimistically on restart"
    );

    let children = kernel.children(parent).unwrap();
    assert_eq!(children.len(), 2);
    let edges = kernel.all_dependencies().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].dependent_task_id, second);
    assert_eq!(edges[0].prerequisite_task_id, first);

    // Completion after the restart still releases the dependent.
    let released = kernel.complete_task(first).unwrap();
    assert_eq!(released, vec![second]);
    assert_eq!(
        task_store.get_task(&second).unwrap().unwrap().state,
        TaskState::Ready
    );
}

#[test]
fn readiness_and_completion_are_recorded_in_the_ledger() {
    let rig = Rig::new();
    let parent = rig.running_parent();
    let kernel = rig.kernel();

    let prerequisite = kernel
        .create_child(parent, ChildTaskSpec::new("a", ""))
        .unwrap();
    rig.start(prerequisite);
    let dependent = kernel
        .create_child(parent, ChildTaskSpec::new("b", "").depends_on(prerequisite))
        .unwrap();

    kernel.complete_task(prerequisite).unwrap();
    assert_eq!(rig.state(dependent), TaskState::Ready);

    let events = rig
        .event_bus
        .get_events_for_task(&dependent.to_string())
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "TaskBecameReady"),
        "becoming ready must be auditable"
    );
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "TaskDelegated"),
        "delegation must be auditable"
    );
}
