# Sky OS v2.0 Architecture

## Purpose

Sky OS is a distributed execution runtime for AI agents. Its primary goal is to make autonomous work reliable, reviewable, and recoverable across crashes, model upgrades, and tool misuse.

The system treats the model as one component in a larger execution pipeline. The model may propose an action, but the runtime determines whether it is permitted and records what actually happened.

## Core invariant

The architectural invariant is:

```text
model proposes -> runtime permits -> tool acts -> artifact proves
```

Each stage has a distinct responsibility:

1. **Model:** proposes work, requests tools, and returns structured output.
2. **Runtime:** validates capabilities, evaluates policy, and owns execution state.
3. **Tool:** performs a bounded side effect.
4. **Artifact:** records immutable evidence of the result.

This boundary prevents the model from directly bypassing safety controls or becoming the sole source of truth for completed work.

## System hierarchy

```text
Sky OS
│
├── Sky Runtime
│   ├── Events
│   ├── Tasks
│   ├── Scheduler
│   ├── Permissions
│   ├── State and recovery
│   ├── Artifacts
│   └── Memory
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
│   └── ExecutorAgent
├── Models
│   ├── Ollama
│   ├── llama.cpp
│   └── Cloud adapters
├── Compositions
│   ├── Development
│   ├── Research
│   └── Marketing
└── Clients
    └── CLI
```

## Runtime subsystems

### Event ledger

The event ledger is an append-only record of runtime transitions. Every important state change is written as an immutable event.

Suggested event categories:

- `TaskCreated`
- `TaskClaimed`
- `ToolCallStarted`
- `ToolCallCompleted`
- `ArtifactCreated`
- `TaskCompleted`
- `TaskFailed`
- `TaskBlockedOnRecovery`
- `CapabilityDenied`

The ledger should be durable and should not allow in-place modification of historical records.

### Task engine

The task engine owns the lifecycle of executable work.

```text
CREATED -> READY -> CLAIMED -> RUNNING
                              ├── WAITING / BLOCKED
                              ├── COMPLETED
                              └── FAILED / ESCALATED
```

Every transition must be recorded before the task is considered durably updated.

### Scheduler

The scheduler selects runnable tasks from a durable queue. It should support:

- single-worker and multi-worker operation;
- task ownership and lease expiration;
- blocking on dependencies;
- retry policies;
- dead-letter handling; and
- crash-safe recovery of leased tasks.

A task must not remain permanently claimed after a worker disappears.

### State and recovery

The runtime stores task state in a durable, crash-safe form. After startup, the runtime restores the latest consistent state and evaluates unfinished work.

The recovery process should:

1. load the task ledger and latest checkpoint;
2. identify incomplete transitions;
3. inspect tool-side effects through artifact or external verification;
4. classify the operation by semantics;
5. resume, block, or escalate the task.

### Permission engine

Tools execute only when the assigned capability token contains the required permission.

A capability check is performed before the tool is dispatched:

```text
proposal -> token check -> policy -> tool execution
```

The policy engine should reject missing or insufficient permissions before any external operation starts.

### Artifact registry

The artifact registry stores immutable content-addressable artifacts under a stable local directory, such as `~/.sky/artifacts/`.

Each artifact contains:

- a generated artifact ID;
- an artifact type;
- a SHA-256 content hash;
- byte size;
- creating agent and task IDs;
- parent artifact IDs;
- metadata; and
- a source location URI.

### Memory subsystem

Memory is a runtime subsystem rather than a model-only feature. It stores:

- task history;
- execution logs;
- task state;
- artifact lineage;
- thread or conversation context; and
- semantic indexes for retrieval.

The memory subsystem must not make a policy decision by itself. It provides evidence and context to the runtime and agent.

## Tool primitive contract

Each tool should expose a typed contract:

```rust
pub enum SideEffectProfile {
    None,
    FileSystem,
    ProcessState,
    NetworkCall,
    Arbitrary,
}

pub enum ExecutionSemantics {
    Idempotent,
    AtMostOnce,
    AtLeastOnce,
    Transactional,
}

pub struct ToolContract {
    pub id: String,
    pub version: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub side_effects: SideEffectProfile,
    pub semantics: ExecutionSemantics,
    pub timeout_ms: u64,
    pub requires_capability: String,
}
```

Tool contracts allow the runtime to classify safety, determine recovery behavior, and enforce boundaries without relying on model output.

## Capability namespaces

The initial tool surface is grouped into these capability namespaces:

- `filesystem`
- `process`
- `git`
- `network`
- `browser`
- `database`
- `containers`
- `messaging`
- `scheduler`

Example permissions:

```text
fs.read:/workspace/**
fs.write:/workspace/src/**
process.exec:/workspace/**
net.outbound:disabled
git.commit:/workspace/**
```

A capability token should hold the minimum permissions required by an agent or task.

## Execution semantics

The runtime must classify each tool by its side effects and recovery behavior.

| Semantics | Recovery guidance |
| --- | --- |
| `Idempotent` | Safe to re-run after a restart. |
| `AtMostOnce` | Verify external state or block for user confirmation. |
| `AtLeastOnce` | Use durable records and verify completion. |
| `Transactional` | Roll back or complete as a single coordinated unit. |

The choice is a property of the tool contract, not a model preference.

## Artifact lineage

Artifacts are immutable records with content hashes and parent dependencies.

```text
Task
  -> Snapshot A1
  -> Patch A2
  -> Test Log A3
  -> Git Commit A4
```

A lineage query should return:

- task identifier;
- artifact identifier;
- artifact type;
- parent IDs;
- content hash;
- timestamp;
- producing agent; and
- source location.

A complete lineage graph makes it possible to prove what work was performed and why it was accepted.

## Model independence

The model adapter layer standardizes the interaction contract for:

- Ollama;
- llama.cpp;
- OpenAI-compatible APIs; and
- Anthropic-compatible APIs.

Model adapters must provide a common interface for:

- completion;
- tool calling;
- streaming where supported; and
- structured output.

The kernel must not depend on a specific provider. A model swap must not change the task engine, permission policy, recovery logic, or artifact handling.

## Security boundaries

The runtime should enforce the following boundaries:

- check capabilities before tool calls;
- validate all tool arguments against schemas;
- enforce path restrictions;
- forbid unintended outbound network access;
- apply execution timeouts;
- isolate process and container execution;
- prevent arbitrary state mutation outside the runtime; and
- require durable evidence for completion.

A denied operation must stop at the runtime boundary. It must not fall through to a best-effort implementation.

## Development boundary

The initial implementation should not include:

- visual avatars;
- gaze tracking;
- RAG pipelines;
- fine-tuning scripts;
- mobile applications; or
- enterprise integrations.

These components belong after the kernel can execute tasks safely and recover from failures.
