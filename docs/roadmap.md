# Sky OS v2.0 Roadmap

## Verified implementation status (2026-10-23)

Status was established by inspecting the code and running `cargo test --workspace`
(117 tests passing across `kernel`, `tools`, `agents`, and `sky-cli`).

| Phase | Claimed in this document | Verified reality |
| --- | --- | --- |
| Phase 0 — Kernel core | Required output list below | **Mostly implemented.** Event ledger (`kernel/src/events`), durable task state machine (`kernel/src/tasks/state.rs`), checkpoints + crash-recovery engine with idempotent/at-most-once/reconcilable semantics (`kernel/src/tasks/checkpoint.rs`, `kernel/src/recovery.rs`), CAS artifact registry with lineage (`kernel/src/artifacts`), SQLite WAL persistence (`kernel/src/persistence`). **Missing:** scheduler and task claims/leases — no scheduler code exists. |
| Phase 1 — Layer-0 tools | Filesystem, process, git, network, containers | **Implemented** via `UnifiedToolRegistry` (tools/src/registry.rs) with typed schemas, capability-gated dispatch, and per-tool side-effect semantics. Also includes `hardware` and `domain` tools beyond the planned set. Network tool is local bind/datagram only (no outbound HTTP tool). |
| Phase 2 — Agent runtime | observe/propose/permit/act loop with budgets | **Implemented** in `agents/src/executor.rs`: budget enforcement (steps, wall time, repairs), grant re-check before every dispatch, fail-closed on missing/expired grants, model-proposed actions through the unified dispatcher. |
| Phase 3 — Autonomy benchmarks A0–A4 | Benchmark suite | **Not implemented.** No `tests/autonomy/` suite exists. |
| Phase 4 — Persistence, crash recovery, capability tests A5–A8 | Capability tests | **Partially:** crash-recovery mechanics exist in the kernel with unit tests; the A5–A8 benchmark suite and network-permission enforcement tests do not. |
| Phase 5 — Model abstraction | Ollama, llama.cpp, cloud adapters | **Abstraction only.** `models/src/provider.rs` defines `ModelProvider`/`ActionProposal` and the executor consumes it; no concrete Ollama/llama.cpp/cloud adapter is implemented. |
| Phase 6 — Memory subsystem | — | Not implemented. |
| Phase 7 — Multi-agent compositions | — | Not implemented. |
| Phase 8 — Enterprise workflows | — | Not implemented. |
| Phase 9 — Distributed cluster | — | Not implemented. |
| Phase 10 — Tauri/mobile clients | — | Not implemented; CLI (`sky`) is the only client. |

Build health: the workspace previously failed to compile (two errors in `kernel`:
missing `From<DatabaseError>` for `RecoveryError`, and an invalid empty `Params`
argument in `CheckpointStore::list_unresolved`). Both were fixed on 2026-10-23,
as were three Windows file-lock failures in the checkpoint tests. The claims of
"HMAC signing, IPC bridge, Integration SDK, client output normalizer/PDM
renderer, and Cognitive Core" found in external planning documents do **not**
correspond to any code in this repository and should not be treated as delivered.

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
