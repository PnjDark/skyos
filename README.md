# Sky OS

Sky OS is a hardened, long-lived distributed execution runtime for AI agents. It separates model proposals from runtime permission checks, tool execution, durable task state, and artifact-proven outcomes.

> **Current status (verified 2026-10-23):** The kernel, tool layer, bounded agent executor, model-provider abstraction, and CLI are implemented and tested — 117 tests pass across the workspace (`cargo test --workspace`). The scheduler with task leases, distributed operation, memory subsystem, and visual clients are not implemented. See [docs/roadmap.md](docs/roadmap.md) for the evidence-based per-phase status.

## Core invariant

Sky is designed around this rule:

> The model proposes, the runtime permits, the tool acts, and the artifact proves.

This prevents a model from directly deciding whether an action is safe, allowed, or complete. Runtime policy, durable task state, and content-addressable artifacts provide the trusted execution boundary.

## Architecture at a glance

```text
Sky OS
├── Runtime
│   ├── Events and event ledger
│   ├── Task state and recovery
│   ├── Scheduler and claims
│   ├── Capability and policy enforcement
│   ├── Artifact registry
│   └── Memory subsystem
├── Tools
│   ├── Filesystem
│   ├── Process
│   ├── Git
│   ├── Network
│   ├── Browser
│   ├── Database
│   ├── Containers
│   ├── Messaging
│   └── Scheduler
├── Agents
│   └── Executor with explicit budgets and tool limits
├── Models
│   ├── Ollama
│   ├── llama.cpp
│   └── Cloud providers
├── Compositions
│   ├── Development workflows
│   ├── Research pipelines
│   └── Marketing and enterprise services
└── Clients
    └── CLI
```

For the full architecture and subsystem boundaries, see [docs/architecture.md](docs/architecture.md).
For Sky's character, voice, model-freedom requirements, and visual reference placeholders, see [docs/persona.md](docs/persona.md).

## Getting started

### Prerequisites

- Rust 1.98 or a newer compatible toolchain
- Cargo
- Git

Verify the toolchain:

```powershell
rustc --version
cargo --version
```

### Build

```powershell
cargo build
```

### Run

```powershell
cargo run --bin sky -- --help
```

Create a task and copy its printed UUID into `$taskId`:

```powershell
cargo run --bin sky -- task create "Test Phase 0 Execution"
$taskId = "paste-the-printed-task-uuid-here"
cargo run --bin sky -- task run-snapshot $taskId --workspace . --file-name "demo_snapshot.txt"
cargo run --bin sky -- artifact list $taskId
cargo run --bin sky -- audit log $taskId
```

Do not include angle brackets around the UUID in PowerShell; `<` is parsed as
an operator. Use `cargo run --bin sky -- task list` to list existing tasks.

## Project roadmap

The implementation is planned in phases:

1. **Phase 0 — Kernel core:** event bus, task state machine, recovery, and artifact registry.
2. **Phase 1 — Layer 0 tools:** filesystem, process, Git, containers, and network capabilities.
3. **Phase 2 — Agent runtime:** bounded executor lifecycle and budgets.
4. **Phase 3 — Autonomy benchmarks A0–A4.**
5. **Phase 4 — Persistence, crash recovery, and capability tests A5–A8.**
6. **Phase 5 — Model abstraction and adapters.**
7. **Phase 6 — Memory subsystem and context resolution.**
8. **Phase 7 — Multi-agent compositions.**
9. **Phase 8 — Enterprise workflows.**
10. **Phase 9 — Distributed worker cluster.**
11. **Phase 10 — Tauri and mobile clients.**

See [docs/roadmap.md](docs/roadmap.md) for the full plan and milestone targets.

## Milestone 0

The first implementation milestone is a CLI task runner that:

- accepts a task from the command line, such as `sky task run "Fix auth bug"`;
- operates on a real repository through deterministic tools;
- survives a forced process termination;
- resumes and completes the task without duplicate side effects;
- records a verifiable SHA-256 artifact lineage; and
- reports the changes it made.

See [docs/milestone-0.md](docs/milestone-0.md) for the acceptance criteria and implementation checklist.

## Autonomy benchmark suite

The project will validate stability and autonomy with benchmarks A0–A9. These tests cover reading unfamiliar repositories, implementing features, executing tests, self-repair, Git operations, crash recovery, permission enforcement, artifact audits, and model independence.

See [tests/autonomy/README.md](tests/autonomy/README.md) when the benchmark suite is created.

## Development principles

- **Runtime-owned state:** the runtime owns task state, events, recovery data, and artifacts.
- **Capability-based access:** tools require explicit capability tokens.
- **Typed tool contracts:** every tool declares side effects, semantics, timeout, schema, and required capability.
- **Deterministic execution:** task state transitions are recorded before completion becomes durable.
- **Artifact lineage:** every result references its parent artifacts and content hash.
- **Model-independent behavior:** model adapters must not change task execution mechanics.
- **No premature UI:** visual clients and prompt templates come after the kernel can execute reliably.

## Contributing

Create a focused feature branch for each change. Keep runtime, tool, agent, model, composition, and client code separated by workspace crates. Add tests for every behavior that can affect safety, recovery, or determinism.

Before accepting a feature into the mainline roadmap, verify it against the relevant autonomy benchmark and provide evidence of its behavior.

## Repository layout

```text
sky-os/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── roadmap.md
│   └── milestone-0.md
├── kernel/
├── tools/
├── agents/
├── models/
├── compositions/
├── clients/
└── tests/
```
