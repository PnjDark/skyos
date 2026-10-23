# Milestone 0: Hardened CLI Execution

## Goal

Milestone 0 establishes the minimum reliable foundation for Sky OS.

Sky must accept a command-line task, execute it through deterministic tools, survive a forced termination, resume safely, generate an artifact lineage, and report the final change.

## Target command

```powershell
sky task run "Fix auth bug"
```

## Acceptance criteria

### 1. Task reception

The CLI must accept a task description and create a durable task record.

### 2. Deterministic tool execution

The task runner must call filesystem, Git, test, and other safe tools through typed contracts. Tool invocation must use runtime validation rather than raw model-generated commands.

### 3. Process survival

A forced termination during execution must not leave the task in an ambiguous state.

The runtime must:

- persist the current task state;
- record the event that occurred before termination;
- identify the incomplete operation on restart;
- apply the tool's recovery semantics; and
- continue without creating duplicate side effects.

### 4. Safe recovery

For each unfinished tool call:

- `Idempotent`: re-run safely;
- `AtMostOnce`: verify external state or block;
- `AtLeastOnce`: verify completion before marking done;
- `Transactional`: complete or roll back as one unit.

### 5. Artifact lineage

Every completed task must produce artifacts with:

- unique IDs;
- content hashes;
- parent dependencies;
- task association;
- producer metadata; and
- a durable location.

### 6. Verification

The final result must include a summary of:

- the task;
- the durable task ID;
- the executed tools;
- produced artifacts;
- parent-child lineage;
- verification steps; and
- any blocked or escalated work.

### 7. No duplicate effects

Running the recovery path must not duplicate a non-idempotent action. If duplicate action risk is detected, the task must stop and require user confirmation.

## Suggested implementation sequence

1. Define the task and event schemas.
2. Add a durable task store.
3. Implement task creation and claim transitions.
4. Add a minimal tool registry and contracts.
5. Add capability token validation.
6. Implement filesystem and Git tools.
7. Support test execution as a tool step.
8. Persist checkpoints and events.
9. Implement restart recovery.
10. Add artifact creation and lineage queries.
11. Add forced-termination integration tests.
12. Validate the CLI output against the acceptance criteria.

## Minimum test coverage

The milestone should include tests for:

- task creation;
- task claim and release;
- checkpoint persistence;
- safe recovery after process termination;
- idempotent re-execution;
- duplicate-action prevention;
- capability denial;
- artifact hash verification;
- parent and child lineage traversal; and
- final task reporting.

## Definition of done

Milestone 0 is complete only when the complete runtime sequence is demonstrated and the generated artifacts prove the exact result without relying on a model-generated summary.
