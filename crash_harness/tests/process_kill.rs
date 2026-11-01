/// Phase 5.3 — Process-Kill Recovery gate.
///
/// Every test here spawns a **real worker process** that writes to a **real
/// SQLite WAL database** and mutates a **real Git repository**, dies at a chosen
/// boundary, and is followed by one or more *fresh* processes that reopen the
/// same database and recover.
///
/// Nothing is mocked: the commit hashes reported here exist on disk, and the
/// duplicate-side-effect assertions count actual commits in the repository.
///
/// Crash matrix
/// ────────────
/// | boundary                              | exit | required verdict                  |
/// |---------------------------------------|------|-----------------------------------|
/// | after Pending, before Dispatched      |  70  | RetryReady, zero side effects      |
/// | after Dispatched, before invocation   |  71  | OutcomeUnknown, task Blocked       |
/// | after side effect, before checkpoint  |  72  | OutcomeUnknown, zero duplicates    |
/// | after result persisted, before finish |  73  | Succeeded, recovery is a no-op     |
/// | externally killed at the boundary     | kill | OutcomeUnknown, durability intact  |
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const WORKER: &str = env!("CARGO_BIN_EXE_sky-crash-worker");

// ── Harness ───────────────────────────────────────────────────────────────────

struct Harness {
    _dir: tempfile::TempDir,
    db: PathBuf,
    repo: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        Self::git(&repo, &["init"]);
        Self::git(&repo, &["config", "user.name", "Sky Crash Harness"]);
        Self::git(
            &repo,
            &["config", "user.email", "crash-harness@sky.invalid"],
        );
        std::fs::write(repo.join("seed.txt"), "seed\n").unwrap();
        Self::git(&repo, &["add", "--", "seed.txt"]);
        Self::git(&repo, &["commit", "-m", "initial"]);

        // Leave one change staged so that any dispatched commit has real work
        // to do.  This is what makes a "duplicate commit" physically possible.
        std::fs::write(repo.join("work.txt"), "side effect payload\n").unwrap();
        Self::git(&repo, &["add", "--", "work.txt"]);

        Self {
            db: dir.path().join("runtime_state.db"),
            repo,
            _dir: dir,
        }
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git must be installed for the Phase 5.3 gate");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn stage(&self, name: &str, content: &str) {
        std::fs::write(self.repo.join(name), content).unwrap();
        Self::git(&self.repo, &["add", "--", name]);
    }

    fn commit_count(&self) -> usize {
        let output = Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(&self.repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("commit count")
    }

    fn head(&self) -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&self.repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn report(&self, name: &str) -> PathBuf {
        self._dir.path().join(name)
    }

    fn worker(&self, command: &str) -> Command {
        let mut cmd = Command::new(WORKER);
        cmd.arg(command)
            .arg("--db")
            .arg(&self.db)
            .arg("--repo")
            .arg(&self.repo);
        cmd
    }

    fn run(&self, boundary: &str, crash: &str, report: &str) -> Output {
        self.worker("run")
            .arg("--boundary")
            .arg(boundary)
            .arg("--crash")
            .arg(crash)
            .arg("--report")
            .arg(self.report(report))
            .output()
            .expect("worker must launch")
    }

    fn run_expecting(&self, boundary: &str, crash: &str, report: &str, code: i32) -> Value {
        let output = self.run(boundary, crash, report);
        assert_eq!(
            output.status.code(),
            Some(code),
            "unexpected exit for boundary {boundary}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.read(report)
    }

    fn execute(&self, command: &mut Command, report: &str) -> Value {
        let output = command
            .arg("--report")
            .arg(self.report(report))
            .output()
            .expect("worker must launch");
        assert!(
            output.status.success(),
            "worker command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.read(report)
    }

    fn recover(&self, report: &str) -> Value {
        self.execute(&mut self.worker("recover"), report)
    }

    fn authorize(&self, report: &str) -> Value {
        self.execute(&mut self.worker("authorize"), report)
    }

    fn resume(&self, report: &str) -> Value {
        self.execute(&mut self.worker("resume"), report)
    }

    fn resume_blind(&self, report: &str) -> Value {
        let mut command = self.worker("resume");
        command.arg("--blind");
        self.execute(&mut command, report)
    }

    fn reconcile(&self, evidence: &str, report: &str) -> Value {
        let mut command = self.worker("reconcile");
        command.arg("--evidence").arg(evidence);
        self.execute(&mut command, report)
    }

    fn inspect(&self, report: &str) -> Value {
        self.execute(&mut self.worker("inspect"), report)
    }

    fn requeue(&self, report: &str) -> Value {
        self.execute(&mut self.worker("requeue"), report)
    }

    fn authorize_with_denying_policy(&self, report: &str) -> Value {
        let mut command = self.worker("authorize");
        command.arg("--policy").arg("deny");
        self.execute(&mut command, report)
    }

    fn read(&self, name: &str) -> Value {
        let path = self.report(name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("missing report {}: {error}", path.display()));
        serde_json::from_str(&raw).expect("report must be JSON")
    }

    fn checkpoint_status(&self, section: &str) -> Value {
        self.inspect(section)["tasks"][0]["checkpoint_status"].clone()
    }

    fn task_state(&self, section: &str) -> Value {
        self.inspect(section)["tasks"][0]["state"].clone()
    }

    /// Spawn a worker that parks at the boundary, then terminate it **from the
    /// parent process**.
    ///
    /// `Child::kill` is the platform's forced termination: `TerminateProcess` on
    /// Windows and `kill(pid, SIGKILL)` on Unix.  The worker never gets to run a
    /// destructor, flush a buffer, or exit on its own terms.
    fn spawn_and_kill(&self, boundary: &str, report: &str) -> std::process::ExitStatus {
        let mut child = self
            .worker("run")
            .arg("--boundary")
            .arg(boundary)
            .arg("--crash")
            .arg("wait")
            .arg("--report")
            .arg(self.report(report))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("worker must launch");

        let marker = self.report(report).with_extension("ready");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !marker.exists() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker never reached the kill boundary");
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        child
            .kill()
            .expect("the parent must be able to kill the worker");
        child.wait().expect("the killed worker must be reaped")
    }
}

// ── Boundary 1 — after Pending, before Dispatched ────────────────────────────

#[test]
fn crash_after_pending_leaves_no_side_effect() {
    let harness = Harness::new();
    assert_eq!(harness.commit_count(), 1);

    let report = harness.run_expecting("pending", "exit", "run-pending.json", 70);

    assert_eq!(report["checkpoint_status"], "Pending");
    assert_eq!(report["task_state"], "Running");
    assert_eq!(
        harness.commit_count(),
        1,
        "a crash before dispatch must leave the repository untouched"
    );
}

#[test]
fn pending_crash_is_retry_ready_and_retries_exactly_once() {
    let harness = Harness::new();
    harness.run_expecting("pending", "exit", "run-pending.json", 70);

    let recovered = harness.recover("recover.json");
    assert_eq!(recovered["recovered"], 1);
    assert_eq!(
        recovered["decisions"][0]["decision"],
        "RetryReadyNeverDispatched"
    );

    let resumed = harness.resume("resume.json");
    assert_eq!(resumed["dispatched"], 1);
    assert_eq!(
        harness.commit_count(),
        2,
        "the retried operation must happen exactly once"
    );

    // A second resume has nothing retry-ready and must not commit again.
    let again = harness.resume("resume-again.json");
    assert_eq!(again["dispatched"], 0);
    assert_eq!(harness.commit_count(), 2);
    assert_eq!(
        harness.checkpoint_status("inspect.json"),
        Value::String("Succeeded".into())
    );
}

// ── Boundary 2 — after Dispatched, before the tool invocation ────────────────

#[test]
fn crash_after_dispatch_blocks_the_task_without_duplicating() {
    let harness = Harness::new();

    let report = harness.run_expecting("dispatched", "exit", "run-dispatched.json", 71);
    assert_eq!(report["checkpoint_status"], "Dispatched");
    assert_eq!(harness.commit_count(), 1);

    let recovered = harness.recover("recover.json");
    assert_eq!(recovered["recovered"], 1);
    assert_eq!(recovered["decisions"][0]["decision"], "OutcomeUnknown");
    assert_eq!(recovered["obligations"][0]["state"], "Blocked");
    assert_eq!(
        harness.checkpoint_status("inspect.json"),
        Value::String("OutcomeUnknown".into())
    );

    // Recovery must not have authorized anything.
    let authorized = harness.authorize("authorize.json");
    assert_eq!(
        authorized["attempts"].as_array().unwrap().len(),
        0,
        "an OutcomeUnknown step is not retry-eligible"
    );
    assert_eq!(authorized["recorded_decisions"], 0);

    let resumed = harness.resume("resume.json");
    assert_eq!(resumed["dispatched"], 0);
    assert_eq!(
        harness.commit_count(),
        1,
        "an uncertain dispatch must never be replayed"
    );

    // Control experiment: bypassing the guard *does* create the duplicate,
    // proving the refusal above is what prevented it.
    let blind = harness.resume_blind("resume-blind.json");
    assert_eq!(blind["dispatched"], 1);
    assert_eq!(
        harness.commit_count(),
        2,
        "the naive retry the guard forbids is physically possible"
    );
}

// ── Boundary 3 — after the physical side effect, before the checkpoint ───────

#[test]
fn crash_after_the_side_effect_preserves_the_commit_and_never_replays_it() {
    let harness = Harness::new();

    let report = harness.run_expecting("after-effect", "exit", "run-effect.json", 72);
    assert_eq!(report["checkpoint_status"], "Dispatched");
    let commit_hash = report["commit_hash"]
        .as_str()
        .expect("the worker must report the commit it made");
    assert_eq!(
        harness.commit_count(),
        2,
        "the physical commit exists although the checkpoint never recorded it"
    );
    assert_eq!(
        harness.head(),
        commit_hash,
        "the reported hash must be the real HEAD of the repository"
    );

    let recovered = harness.recover("recover.json");
    assert_eq!(recovered["decisions"][0]["decision"], "OutcomeUnknown");
    assert_eq!(harness.task_state("inspect.json"), "Blocked");

    // Make a second commit physically possible, so the refusal below is a real
    // guard rather than the tool refusing for lack of staged work.
    harness.stage("followup.txt", "follow up\n");

    let resumed = harness.resume("resume.json");
    assert_eq!(resumed["dispatched"], 0);
    assert_eq!(
        harness.commit_count(),
        2,
        "recovery must not create a duplicate commit"
    );

    // Physical evidence — discovered by probing the repository, not asserted by
    // the caller — resolves the uncertainty without re-executing anything.
    let reconciled = harness.reconcile("discover", "reconcile.json");
    assert_eq!(reconciled["verdicts"][0]["verdict"], "MarkedSucceeded");
    let evidence = reconciled["verdicts"][0]["evidence"]
        .as_str()
        .expect("the probe must report what it found");
    assert!(
        evidence.contains(commit_hash),
        "the reconciler must discover the commit the crashed worker reported: {evidence}"
    );
    assert_eq!(
        reconciled["verdicts"][0]["actor_kind"], "Operator",
        "the reconciliation decision must be attributable to a verified actor"
    );
    assert_eq!(
        reconciled["verdicts"][0]["auth_method"], "HarnessOnly",
        "the recorded method must not claim more than the harness provides"
    );

    let inspected = harness.inspect("inspect-after.json");
    assert_eq!(inspected["tasks"][0]["checkpoint_status"], "Succeeded");
    let records = &inspected["tasks"][0]["reconciliations"];
    assert_eq!(records.as_array().unwrap().len(), 1);
    assert_eq!(records[0]["action"], "AdoptExistingArtifact");
    assert_eq!(records[0]["prior_status"], "OutcomeUnknown");
    assert_eq!(records[0]["new_status"], "Succeeded");

    assert_eq!(
        harness.commit_count(),
        2,
        "reconciliation observes the world; it never mutates it"
    );
}

#[test]
fn proven_absent_effect_authorizes_a_single_retry() {
    let harness = Harness::new();

    harness.run_expecting("dispatched", "exit", "run-dispatched.json", 71);
    harness.recover("recover.json");

    // Suppose the operator can prove from physical evidence that the attempt
    // never reached the repository (HEAD equals the pre-dispatch value).  The
    // probe establishes that on its own.
    let reconciled = harness.reconcile("discover", "reconcile.json");
    assert_eq!(reconciled["verdicts"][0]["verdict"], "RetryAuthorized");

    // Retryability is still not authorization: the task remains Blocked and is
    // not silently revived.
    let premature = harness.resume("resume-premature.json");
    assert_eq!(
        premature["dispatched"], 0,
        "a blocked task must be re-queued before it can run again"
    );

    // The operator re-queues the reconciled task, then resumption is authorized.
    let requeued = harness.requeue("requeue.json");
    assert_eq!(requeued["requeued"].as_array().unwrap().len(), 1);

    let inspected = harness.inspect("inspect-requeued.json");
    let records = &inspected["tasks"][0]["reconciliations"];
    let actions: Vec<&str> = records
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["AuthorizeRetry", "RequeueForExecution"]);
    assert_eq!(records[1]["actor_id"], "crash-harness-operator");
    assert_eq!(records[1]["prior_status"], "Blocked");

    let resumed = harness.resume("resume.json");
    assert_eq!(resumed["dispatched"], 1);
    assert_eq!(harness.commit_count(), 2);

    // And the retry is not retried again.
    let again = harness.resume("resume-again.json");
    assert_eq!(again["dispatched"], 0);
    assert_eq!(harness.commit_count(), 2);
}

// ── Boundary 4 — after the result is persisted, before task completion ───────

#[test]
fn crash_after_result_persistence_is_a_no_op_for_recovery() {
    let harness = Harness::new();

    let report = harness.run_expecting("after-result", "exit", "run-result.json", 73);
    assert_eq!(report["checkpoint_status"], "Succeeded");
    assert_eq!(
        report["task_state"], "Running",
        "the task had not yet transitioned to Completed when the process died"
    );
    assert_eq!(harness.commit_count(), 2);

    let recovered = harness.recover("recover.json");
    assert_eq!(
        recovered["recovered"], 0,
        "a terminal checkpoint is not an unresolved invocation"
    );
    assert_eq!(harness.commit_count(), 2);
}

// ── Genuine external process termination ─────────────────────────────────────

#[test]
fn externally_killed_process_leaves_a_durable_unknown_outcome() {
    let harness = Harness::new();

    // The worker performs the real commit, reports it, and then parks until the
    // parent terminates it.  `Child::kill` is TerminateProcess on Windows and
    // SIGKILL on Unix: no destructors, no flush, no graceful shutdown.
    let status = harness.spawn_and_kill("after-effect", "kill.json");

    assert!(
        !status.success(),
        "the worker must be terminated externally, not exit on its own"
    );
    assert!(
        !matches!(status.code(), Some(0 | 70 | 71 | 72 | 73)),
        "the worker must not have reached one of its own crash boundaries: {status:?}"
    );

    let report = harness.read("kill.json");
    assert_eq!(report["checkpoint_status"], "Dispatched");
    assert_eq!(harness.commit_count(), 2);

    let recovered = harness.recover("recover.json");
    assert_eq!(
        recovered["decisions"][0]["decision"], "OutcomeUnknown",
        "the database must reopen after an abrupt kill and still classify correctly"
    );
    assert_eq!(harness.task_state("inspect.json"), "Blocked");
    assert_eq!(
        harness.commit_count(),
        2,
        "no duplicate may appear after an external kill"
    );

    // The commit the killed process made is discoverable afterwards.
    let reconciled = harness.reconcile("discover", "reconcile.json");
    assert_eq!(reconciled["verdicts"][0]["verdict"], "MarkedSucceeded");
    let expected = report["commit_hash"].as_str().unwrap();
    assert!(
        reconciled["verdicts"][0]["evidence"]
            .as_str()
            .unwrap()
            .contains(expected)
    );
    assert_eq!(harness.commit_count(), 2);
}

#[test]
fn requeue_is_refused_while_the_outcome_is_unknown() {
    let harness = Harness::new();
    harness.run_expecting("dispatched", "exit", "run-dispatched.json", 71);
    harness.recover("recover.json");

    let refused = harness.requeue("requeue.json");
    assert_eq!(
        refused["requeued"].as_array().unwrap().len(),
        0,
        "a task with an OutcomeUnknown step must not be re-queued"
    );
    assert_eq!(refused["refused"].as_array().unwrap().len(), 1);
    assert_eq!(harness.task_state("inspect.json"), "Blocked");
    assert_eq!(harness.commit_count(), 1);
}

// ── Recovery idempotency across processes ────────────────────────────────────

#[test]
fn repeated_recovery_in_fresh_processes_is_idempotent() {
    let harness = Harness::new();
    harness.run_expecting("dispatched", "exit", "run-dispatched.json", 71);

    let first = harness.recover("recover-1.json");
    assert_eq!(first["recovered"], 1);

    let second = harness.recover("recover-2.json");
    assert_eq!(
        second["recovered"], 0,
        "re-running recovery must not re-classify a settled checkpoint"
    );

    let inspected = harness.inspect("inspect.json");
    assert_eq!(inspected["tasks"][0]["checkpoint_status"], "OutcomeUnknown");
    assert_eq!(harness.commit_count(), 1);
}

// ── Phase 5.2 end-to-end: policy denial after an offline change ──────────────

#[test]
fn offline_policy_tightening_refuses_the_retry_end_to_end() {
    let harness = Harness::new();
    harness.run_expecting("pending", "exit", "run-pending.json", 70);
    harness.recover("recover.json");

    let authorized = harness.authorize_with_denying_policy("authorize.json");
    assert_eq!(authorized["attempts"][0]["result"], "refused");
    assert_eq!(
        authorized["recorded_decisions"], 1,
        "the refusal itself must be durably recorded"
    );
    assert_eq!(harness.task_state("inspect.json"), "Failed");

    let resumed = harness.resume("resume.json");
    assert_eq!(resumed["dispatched"], 0);
    assert_eq!(
        harness.commit_count(),
        1,
        "a revoked grant on recovery must never reach the repository"
    );
}
