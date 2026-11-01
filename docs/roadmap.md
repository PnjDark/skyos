# Sky OS v2.0 Roadmap

## Verified implementation status (2026-10-30)

Status was established by inspecting the code and running the workspace test
suite. Test-count history: 117 (2026-10-23) → 234 at the Phase 5 acceptance
gate → 260 at Phase 6.0 → 309 at Phase 6.1C, all on 2026-10-30.

**Re-run on 2026-10-30:** `cargo test --workspace --exclude agents --exclude
sky-cli` passes **247/247 across 25 targets** (exit 0), and clippy with
`-D warnings` is clean for the same set. The *unfiltered* `cargo test
--workspace` currently **fails to compile**: `agents/src/executor.rs` — part of
the in-flight Phase 6.1D cancellation work — calls `ExecutionGuard`,
`cancellation_pending` and `cancel_and_stop`, none of which exist in the tree
yet (7 errors first attempt, 9 on retry while the file was being edited). That
blocks a complete workspace number, not the crates listed below. Raw evidence:
`docs/phase5/evidence/*_2026-10-30.txt`.

| Phase | Claimed in this document | Verified reality |
| --- | --- | --- |
| Phase 0 — Kernel core | Required output list below | **Mostly implemented.** Event ledger (`kernel/src/events`), durable task state machine (`kernel/src/tasks/state.rs`), checkpoints + crash-recovery engine with idempotent/at-most-once/reconcilable semantics (`kernel/src/tasks/checkpoint.rs`, `kernel/src/recovery/`), CAS artifact registry with lineage (`kernel/src/artifacts`), SQLite WAL persistence (`kernel/src/persistence`). **Missing:** scheduler and task claims/leases — no scheduler code exists. |
| Phase 1 — Layer-0 tools | Filesystem, process, git, network, containers | **Implemented** via `UnifiedToolRegistry` (tools/src/registry.rs) with typed schemas, capability-gated dispatch, and per-tool side-effect semantics. Also includes `hardware` and `domain` tools beyond the planned set. Network tool is local bind/datagram only (no outbound HTTP tool). |
| Phase 2 — Agent runtime | observe/propose/permit/act loop with budgets | **Implemented** in `agents/src/executor.rs`: budget enforcement (steps, wall time, repairs), grant re-check before every dispatch, fail-closed on missing/expired grants, model-proposed actions through the unified dispatcher. |
| Phase 3A — `RepositoryProvisioner` (Software Factory) | Isolated worktree provisioning | **Implemented + integration gate passed (2026-10-23)** (`provisioner/` crate + `sky_cli::workspace`). Evidence: 8 provisioner tests + 10 governed-gate tests pass; full workspace suite 135/135; live CLI smoke test on a real git repo verified (a) fail-closed without capabilities, (b) authorized provisioning creating a real `git worktree` on `feat/smoke`, (c) idempotent repeat returning the identical context, (d) ledger audit chain `PermissionDenied→WorkspaceProvisioningFailed` for the denied attempt and `PermissionGranted→WorkspaceProvisioningStarted→WorkspaceProvisioned` for the authorized runs. Authorization reuses existing `GitWrite` + `FileSystemWrite` capabilities through `PolicyEngine` — no new grant variants. `sky workspace provision` / `sky workspace recover` are the CLI surfaces. **Remaining limitations:** `SnapshotToBranch` dirty-tree policy fails closed as unimplemented; unix symlink-escape tests are `#[cfg(unix)]` and unverified on this Windows host; provisioning is not yet invoked by the agent executor loop (CLI/manual only). |
| Phase 3B — `skyos-transform` (OCC engine) | — | **Implemented.** `transform/` crate: 3B.1 content-addressed revision store, 3B.2 optimistic concurrency control, 3B.3 atomic multi-file publication + filesystem materializer. Tests: `revision_store_tests`, `occ_tests`, `transaction_tests`. |
| Phase 3 — Autonomy benchmarks A0–A4 | Benchmark suite | **Not implemented.** No `tests/autonomy/` suite exists. |
| Phase 4 — Persistence, crash recovery, capability tests A5–A8 | Capability tests | **Partially:** crash-recovery mechanics exist in the kernel with unit tests; the A5–A8 benchmark suite and network-permission enforcement tests do not. |
| Phase 5 — Model abstraction (this document's numbering) | Ollama, llama.cpp, cloud adapters | **In progress.** `models/src/provider.rs` defines `ModelProvider`/`ActionProposal`, which the executor consumes. First concrete adapter landed 2026-10-30: `OllamaModelProvider` (`models/src/ollama.rs`, `POST /api/chat`, strict `ActionProposal` parsing, typed `OllamaError` taxonomy for connection failure / timeout / missing model / non-2xx / malformed body / invalid or invented proposal), with 16 offline contract tests in `models/tests/ollama_provider_tests.rs`. **Not implemented:** llama.cpp, OpenAI-compatible and Anthropic-compatible adapters. |
| Phase 5 — Crash recovery & execution semantics (implementation track, `docs/phase5/`) | — not part of this document's numbering | **Accepted and locked (2026-10-30).** Checkpoint classification, fresh-grant re-authorization, crash-injection gate and attributed reconciliation (`kernel/src/recovery/`, `crash_harness/`, `agents/tests/crash_recovery_tests.rs`). Kept separate from the model-abstraction row above: two workstreams share the number "5" and are not one phase. See `docs/phase5/PHASE_5_ACCEPTANCE_GATE.md`. |
| Phase 6 — Memory subsystem | — | Not implemented. |
| Phase 7 — Multi-agent compositions | — | Not implemented. |
| Phase 8 — Enterprise workflows | — | Not implemented. |
| Phase 9 — Distributed cluster | — | Not implemented. |
| Phase 10 — Tauri/mobile clients | — | Not implemented; CLI (`sky`) is the only client. |

### Implementation tracks (the numbering used in code comments and `docs/`)

The roadmap above and the implementation use two independent numbering schemes;
they collide at 5 and 6 (model abstraction vs. crash recovery, memory vs.
governed reconciliation). Both are recorded here rather than merged, so no
historical reference in `docs/phase5/`, `docs/phase6/`, code comments or test
names has to be rewritten.

| Track | Scope | Status (2026-10-30) |
| --- | --- | --- |
| Phase 3A | `RepositoryProvisioner` — governed worktree provisioning | **Implemented**, integration gate passed |
| Phase 3B | `skyos-transform` — OCC + atomic publication | **Implemented**, tests green |
| Phase 5 | Crash recovery & execution semantics | **Accepted and locked** (`docs/phase5/`) |
| Phase 6.0 | Governed reconciliation & authenticated identity | **Implemented and verified** (`docs/phase6/PHASE_6_0_COMPLETION.md`) |
| Phase 6.1A–B | Delegation prerequisites, task/DAG delegation | **Implemented and verified** |
| Phase 6.1C | Budget accounting (M9 → concurrency gates) | **Implemented and verified**, baseline 309 tests |
| Phase 6.1D | Hierarchical cancellation cascade | **In progress** — design signed off in `PHASE_6_1D_CANCELLATION_STATE_MACHINE.md`; `kernel/src/delegation/` is present in the working tree but uncommitted and still being edited |

Build health: the workspace previously failed to compile (two errors in `kernel`:
missing `From<DatabaseError>` for `RecoveryError`, and an invalid empty `Params`
argument in `CheckpointStore::list_unresolved`). Both were fixed on 2026-10-23,
as were three Windows file-lock failures in the checkpoint tests. The claims of
"HMAC signing, IPC bridge, Integration SDK, client output normalizer/PDM
renderer, and Cognitive Core" found in external planning documents do **not**
correspond to any code in this repository and should not be treated as delivered.

## Scheduler gap audit (2026-10-23) — decision: DEFERRED

Audited the kernel against the scheduler requirements table before Phase 3A.
Evidence from `kernel/src/tasks/store.rs` and `persistence/migrations.rs`:

| Capability | Required for | Existing provider | Decision |
| --- | --- | --- | --- |
| Durable task state | Everything | `TaskStore` (SQLite WAL, M2 schema) with compare-and-swap `transition_state` (from-state checked inside a transaction) | **REUSE** |
| Checkpoint & crash recovery | Long-running agents | `CheckpointStore` + `RecoveryEngine` (M4 schema, per-step semantics classification) | **REUSE** |
| Audit evidence | Everything | `EventBus` append-only ledger, written in the same transaction as state changes | **REUSE** |
| Atomic task claiming / competing workers | Multi-worker pools | None. The `Claimed` state exists in the state machine but no code ever transitions into it, and the `tasks` table has no worker/lease columns | **NOT NEEDED YET** |
| Lease expiry & heartbeat | Worker-loss tolerance | None | **NOT NEEDED YET** |
| Cancellation & timeouts | Interactive cancel | Budget engine in `agents/src/executor.rs` (step/wall-time/repair budgets) covers timeouts; no external cancellation signal | **EXTEND LATER** |
| Priority scheduling | Work ordering | `priority` column exists on tasks but nothing orders by it | **NOT NEEDED YET** |

**Decision: do NOT build `scheduler.rs` before Phase 3A.** `RepositoryProvisioner`
needs only a unique `task_id`, file-level staging locks, and canonical path
guards — none of which require a multi-worker claim/lease queue. If concurrent
workers arrive in a later phase, extend `TaskStore` incrementally with
`leased_by` / `lease_expires_at` columns and an atomic claim query rather than
adding a standalone scheduler subsystem.

## Phase 0: Kernel core

Build the foundations without AI or UI components.

### Required output

- append-only event ledger;
- durable task state machine;
- scheduler and task claims;
- state checkpoints;
- recovery and crash analysis;
- content-addressable artifact registry;
- local task and event storage; and
- basic task execution API.

## Phase 1: Layer 0 tools

Implement safe tool primitives under capability tokens.

### Initial namespaces

- `filesystem`
- `process`
- `git`
- `network`
- `containers`

### Tool properties

Every tool must declare:

- typed input and output schemas;
- side-effect profile;
- execution semantics;
- timeout;
- required capability; and
- deterministic failure behavior.

## Phase 2: Minimal agent runtime

Implement a constrained executor that follows this loop:

```text
observe -> propose -> permit -> act -> observe -> record
```

The runtime should enforce:

- per-task tool budgets;
- per-agent capability budgets;
- execution time limits;
- artifact creation requirements; and
- explicit completion checks.

## Phase 3: Autonomy benchmarks A0–A4

The first benchmark set validates that a CLI task can:

- inspect an unfamiliar repository;
- implement a feature;
- discover and run its native test suite;
- repair a deliberately failing test; and
- create a branch, commit, and patch.

## Phase 4: Persistence, crash recovery, and tests A5–A8

This phase validates:

- forced process termination;
- task recovery after restart;
- duplicate side-effect prevention;
- path permission enforcement;
- network permission enforcement;
- artifact lineage audits; and
- task blocking during unsafe recovery.

## Phase 5: Model abstraction

Standardize provider adapters while keeping execution behavior constant.

Planned adapters:

- Ollama;
- llama.cpp;
- OpenAI-compatible endpoints; and
- Anthropic-compatible endpoints.

## Phase 6: Memory subsystem

Integrate durable context and retrieval features:

- relational memory for task and thread history;
- vector search for semantic retrieval;
- context retention policies;
- memory scope controls; and
- lineage-aware context assembly.

## Phase 7: Multi-agent composition

Introduce composition loops such as:

```text
Planner -> Coder -> Tester -> Reviewer
```

Each composition should use the runtime's task and artifact systems rather than creating hidden or uncontrolled model-to-model communication.

## Phase 8: Enterprise workflows

Add higher-order services for marketing, CRM, support, finance, and development workflows.

These workflows should be composed from atomic tools and runtime tasks. They should not be embedded directly in the kernel.

## Phase 9: Distributed cluster

Support remote task claims, worker leases, and coordination across machines.

The initial distributed design should remain compatible with the local runtime and use a minimal trust model for remote workers.

## Phase 10: Visual and mobile clients

After the kernel is proven, add:

- Tauri v2 desktop shell;
- CLI primary client;
- mobile clients; and
- optional visual avatar and gaze interfaces.

The client layer must remain separate from runtime policy and execution.

## Acceptance rule

A phase is complete only when the relevant tests demonstrate the behavior on a real repository or controlled runtime environment. A model output alone is not acceptance evidence.
