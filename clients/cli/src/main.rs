use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use kernel::persistence::db::DatabaseConnectionPool;
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use sky_cli::executor::TrustedExecutor;
use sky_cli::operations::OperationSpec;
use sky_cli::recovery::RecoveryEngine;
use std::path::PathBuf;
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolStatus};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "sky")]
#[command(about = "Sky OS Kernel CLI & Runtime Execution Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage durable tasks
    Task {
        #[command(subcommand)]
        command: TaskCommands,
    },
    /// Inspect registered artifacts
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommands,
    },
    /// Inspect the audit ledger
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// Invoke a registered tool through the unified dispatcher
    Tool {
        #[command(subcommand)]
        command: ToolCommands,
    },
}

#[derive(Subcommand)]
enum TaskCommands {
    /// Create a new durable task
    Create { title: String },
    /// List all registered tasks
    List,
    /// Execute a bounded snapshot operation on a task
    RunSnapshot {
        task_id: Uuid,
        #[arg(short, long, default_value = ".")]
        workspace: PathBuf,
        #[arg(short, long, default_value = "snapshot.txt")]
        file_name: PathBuf,
        #[arg(short, long, default_value = "Sky OS Grounded State Snapshot")]
        content: String,
    },
}

#[derive(Subcommand)]
enum ArtifactCommands {
    /// List registered artifacts for a task
    List { task_id: Uuid },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Inspect the audit ledger for a task
    Log { task_id: Uuid },
}

#[derive(Subcommand)]
enum ToolCommands {
    /// Invoke a registered tool operation through the unified dispatcher
    Run {
        /// Task ID that owns this invocation
        task_id: Uuid,
        /// Tool family: filesystem | process | git | container
        tool_id: String,
        /// Operation name within the tool family
        operation_id: String,
        /// JSON object of operation parameters
        #[arg(short, long, default_value = "{}")]
        params: String,
        /// Workspace or repository root for the operation
        #[arg(short, long, default_value = ".")]
        workspace: PathBuf,
        /// Authorized capability (e.g. "fs.read:/workspace/**")
        /// Format: <type>:<scope>  where type is one of:
        ///   fs-read, fs-write, git-read, git-write, container-run:<image>
        #[arg(long)]
        capability: String,
        /// Optional caller-supplied idempotency key for crash-recovery deduplication
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Print machine-readable JSON schemas for all registered tool operations
    Schemas,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let db_path = DatabaseConnectionPool::default_runtime_path()?;
    let db_pool = DatabaseConnectionPool::open(&db_path)?;
    let runtime_dir = db_path
        .parent()
        .context("Runtime database path has no parent directory")?;
    let event_bus = EventBus::open(&db_path)?;
    let task_store = TaskStore::open(&db_path)?;

    let cas_dir = runtime_dir.join("artifacts").join("cas");
    let mut artifact_registry = ArtifactRegistry::open(&db_path, cas_dir)?;
    let grant_issuer = GrantIssuer::new();

    let domain_store = kernel::domain::DomainStore::open(db_pool);
    domain_store.register_domain(&kernel::domain::schemas::FitnessSchema)?;
    domain_store.register_domain(&kernel::domain::schemas::PantrySchema)?;
    domain_store.register_domain(&kernel::domain::schemas::FinanceSchema)?;
    domain_store.register_domain(&kernel::domain::schemas::AcademySchema)?;
    domain_store.register_domain(&kernel::domain::schemas::ProductivitySchema)?;

    // FAIL CLOSED: Propagation of startup reconciliation errors.
    let recovery = RecoveryEngine::new(&task_store, &event_bus);
    let reconciled = recovery.reconcile_orphaned_tasks()?;
    if !reconciled.is_empty() {
        println!(
            "[RECOVERY]: Reconciled {} interrupted tasks to Failed state.",
            reconciled.len()
        );
    }

    match cli.command {
        Commands::Task {
            command: TaskCommands::Create { title },
        } => {
            let task_id = task_store.create_task(&title, TaskState::Created, 10)?;
            println!("Task Created Successfully!");
            println!("ID:       {}", task_id);
            println!("Title:    {}", title);
            println!("State:    {}", TaskState::Created);
        }
        Commands::Task {
            command: TaskCommands::List,
        } => {
            let tasks = task_store.list_tasks()?;
            if tasks.is_empty() {
                println!("No tasks found in runtime ledger.");
            } else {
                println!("{:<38} {:<12} {:<20} TITLE", "TASK ID", "STATE", "PRIORITY");
                println!("{}", "-".repeat(80));
                for t in tasks {
                    println!(
                        "{:<38} {:<12} {:<20?} {}",
                        t.task_id,
                        t.state.to_string(),
                        t.priority,
                        t.title
                    );
                }
            }
        }
        Commands::Task {
            command:
                TaskCommands::RunSnapshot {
                    task_id,
                    workspace,
                    file_name,
                    content,
                },
        } => {
            let mut executor = TrustedExecutor::new(
                &task_store,
                &event_bus,
                &mut artifact_registry,
                &grant_issuer,
            );
            let op = OperationSpec::WriteSnapshot {
                relative_path: file_name,
                content_bytes: content.into_bytes(),
            };
            match executor.execute_operation(task_id, "cli_executor", &workspace, op) {
                Ok(artifact) => {
                    println!("[PROVED]: Bounded operation executed & artifact registered!");
                    println!("SHA-256 Hash: {}", artifact.hash);
                    println!("Location:     {}", artifact.location_uri);
                }
                Err(err) => {
                    eprintln!("[FAILED]: Operation halted: {err:#}");
                    return Err(err);
                }
            }
        }
        Commands::Artifact {
            command: ArtifactCommands::List { task_id },
        } => {
            let artifacts = artifact_registry.get_artifacts_for_task(&task_id.to_string())?;
            if artifacts.is_empty() {
                println!("No artifacts recorded for task {}.", task_id);
            } else {
                println!("{:<65} {:<15} SIZE (BYTES)", "SHA-256 HASH", "TYPE");
                println!("{}", "-".repeat(90));
                for a in artifacts {
                    println!("{:<65} {:<15?} {}", a.hash, a.artifact_type, a.size_bytes);
                }
            }
        }
        Commands::Audit {
            command: AuditCommands::Log { task_id },
        } => {
            let events = event_bus.get_events_for_task(&task_id.to_string())?;
            if events.is_empty() {
                println!("No audit events recorded for task {}.", task_id);
            } else {
                println!("{:<30} {:<25} CREATED AT", "EVENT ID", "TYPE");
                println!("{}", "-".repeat(75));
                for e in events {
                    println!("{:<30} {:<25} {}", e.event_id, e.event_type, e.created_at);
                }
            }
        }

        // ── D8.3: Unified dispatcher CLI ─────────────────────────────────────
        Commands::Tool {
            command: ToolCommands::Schemas,
        } => {
            let schemas = UnifiedToolRegistry::export_schemas();
            println!("{}", serde_json::to_string_pretty(&schemas)?);
        }

        Commands::Tool {
            command:
                ToolCommands::Run {
                    task_id,
                    tool_id,
                    operation_id,
                    params,
                    workspace,
                    capability,
                    idempotency_key,
                },
        } => {
            let parameters: serde_json::Value =
                serde_json::from_str(&params).context("--params must be a valid JSON object")?;

            let cap = parse_capability_flag(&capability, &workspace)
                .with_context(|| format!("Invalid --capability value: {capability:?}"))?;

            let grant = grant_issuer.issue_grant("cli_user", task_id, vec![cap], None);
            let ctx = ToolContext::new(task_id, "cli_user");
            let request = InvocationRequest {
                tool_id,
                operation_id,
                parameters,
                idempotency_key,
            };

            let mut dispatcher =
                UnifiedToolRegistry::new(&event_bus, &mut artifact_registry, &grant_issuer)
                    .with_domain_store(&domain_store);
            let result = dispatcher.dispatch(&ctx, &grant, request, &workspace).await;

            println!("{}", serde_json::to_string_pretty(&result)?);

            if result.status != ToolStatus::Succeeded {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Parse a `--capability` flag string into a `Capability`.
///
/// Accepted formats:
///   fs-read:<absolute-path>
///   fs-write:<absolute-path>
///   git-read:<absolute-path>
///   git-write:<absolute-path>
///   container-run:<image>
///   process-exec:<program>
///   domain-read:<namespace>
///   domain-write:<namespace>
fn parse_capability_flag(flag: &str, workspace: &std::path::Path) -> Result<Capability> {
    let (kind, scope) = flag
        .split_once(':')
        .context("Capability flag must be <type>:<scope>")?;

    Ok(match kind {
        "fs-read" => Capability::FileSystemRead {
            root: PathBuf::from(scope),
        },
        "fs-write" => Capability::FileSystemWrite {
            root: PathBuf::from(scope),
        },
        "git-read" => Capability::GitRead {
            repo_root: PathBuf::from(scope),
        },
        "git-write" => Capability::GitWrite {
            repo_root: PathBuf::from(scope),
        },
        "container-run" => Capability::ContainerRun {
            allowed_image: scope.to_string(),
        },
        "process-exec" => Capability::ProcessExec {
            program: scope.to_string(),
            allowed_args_prefix: vec![],
            allowed_workdir: workspace.to_path_buf(),
        },
        "domain-read" => Capability::DomainAccess {
            namespace: scope.to_string(),
            read_only: true,
        },
        "domain-write" => Capability::DomainAccess {
            namespace: scope.to_string(),
            read_only: false,
        },
        other => anyhow::bail!("Unknown capability type: {other:?}"),
    })
}
