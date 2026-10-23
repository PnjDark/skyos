use crate::process::ProcessToolExecutor;
use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{
    Capability, CapabilityGrant, PolicyDecision, ToolInvocationRequest,
};
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

pub const EVENT_CONTAINER_COMPLETED: &str = "ContainerRunCompleted";
pub const EVENT_CONTAINER_FAILED: &str = "ContainerRunFailed";
pub const EVENT_CONTAINER_CLEANED_UP: &str = "ContainerCleanedUp";

/// Hard limits applied to every container run regardless of caller input.
pub struct ContainerLimits {
    pub cpus: f32,
    pub memory_mb: u64,
    pub pids: u32,
    pub timeout_secs: u64,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            cpus: 1.0,
            memory_mb: 512,
            pids: 64,
            timeout_secs: 60,
        }
    }
}

pub struct ContainerToolExecutor<'a> {
    event_bus: &'a EventBus,
    grant_issuer: &'a GrantIssuer,
    process_executor: ProcessToolExecutor<'a>,
    /// Container runtime binary: "docker" or "podman".
    runtime: String,
}

impl<'a> ContainerToolExecutor<'a> {
    pub fn new(
        event_bus: &'a EventBus,
        grant_issuer: &'a GrantIssuer,
        runtime: impl Into<String>,
    ) -> Self {
        let process_executor = ProcessToolExecutor::new(event_bus, grant_issuer);
        Self {
            event_bus,
            grant_issuer,
            process_executor,
            runtime: runtime.into(),
        }
    }

    /// Run an ephemeral container.
    ///
    /// - `image` must match the `ContainerRun { allowed_image }` capability exactly (or `"*"`).
    /// - `cmd_args` are passed as the container command; no shell interpolation.
    /// - `workspace_mount` is an optional read-only host path mounted at `/workspace` inside the container.
    /// - Resource limits are applied unconditionally.
    /// - The container is removed after exit, timeout, or failure.
    pub async fn run(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        image: &str,
        cmd_args: &[&str],
        workspace_mount: Option<&Path>,
        limits: Option<ContainerLimits>,
    ) -> ToolResult {
        // 1. Policy check
        let req = ToolInvocationRequest::ContainerRun {
            image: image.to_string(),
        };
        let engine = PolicyEngine::new(Some(self.event_bus));
        match engine.evaluate_checked(grant, &req) {
            Ok(PolicyDecision::Allow { .. }) => {}
            Ok(PolicyDecision::Deny { reason }) => {
                return self.fail(
                    ctx,
                    format!("Policy Engine denied container run for image {image:?}: {reason}"),
                );
            }
            Err(e) => {
                return self.fail(ctx, format!("Failed to persist container run audit: {e}"));
            }
        }

        let limits = limits.unwrap_or_default();
        let container_name = format!("sky-{}", Uuid::new_v4());

        // 2. Build argument array — no shell, no privileged, explicit resource caps
        let mut args: Vec<String> = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--network=none".to_string(),
            "--no-healthcheck".to_string(),
            "--security-opt=no-new-privileges".to_string(),
            format!("--cpus={}", limits.cpus),
            format!("--memory={}m", limits.memory_mb),
            format!("--pids-limit={}", limits.pids),
        ];

        if let Some(mount_path) = workspace_mount {
            let host = mount_path.to_string_lossy();
            args.push(format!("--volume={host}:/workspace:ro"));
        }

        args.push(image.to_string());
        args.extend(cmd_args.iter().map(|s| s.to_string()));

        // 3. Issue a ProcessExec grant scoped to the container runtime binary
        let runtime_path = which_runtime(&self.runtime);
        let process_grant = self.grant_issuer.issue_grant(
            &ctx.agent_id,
            ctx.task_id,
            vec![Capability::ProcessExec {
                program: runtime_path.clone(),
                allowed_args_prefix: vec!["run".to_string()],
                allowed_workdir: std::env::current_dir().unwrap_or_default(),
            }],
            Some(chrono::Duration::minutes(5)),
        );

        let result = self
            .process_executor
            .execute_process(
                ctx,
                &process_grant,
                &runtime_path,
                &args,
                &std::env::current_dir().unwrap_or_default(),
                Some(limits.timeout_secs),
            )
            .await;

        // 4. Ensure cleanup regardless of outcome (--rm handles success; force-remove on failure/timeout)
        if result.status != ToolStatus::Succeeded {
            self.force_remove(ctx, &container_name).await;
        }

        // 5. Emit outcome event and return
        match result.status {
            ToolStatus::Succeeded => {
                let stdout = match &result.output {
                    ToolOutput::ProcessResult { stdout, .. } => stdout.clone(),
                    _ => String::new(),
                };
                let _ = self.event_bus.emit_event(
                    Some(&ctx.task_id.to_string()),
                    EVENT_CONTAINER_COMPLETED,
                    json!({
                        "invocation_id": ctx.invocation_id,
                        "image": image,
                        "container_name": container_name,
                        "output_preview": &stdout[..stdout.len().min(256)],
                    }),
                );
                ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: ToolStatus::Succeeded,
                    output: ToolOutput::Text(stdout),
                    artifact: None,
                    error_message: None,
                }
            }
            ToolStatus::TimedOut => self.fail(
                ctx,
                format!(
                    "Container {container_name} timed out after {} seconds",
                    limits.timeout_secs
                ),
            ),
            _ => {
                let msg = result
                    .error_message
                    .unwrap_or_else(|| format!("Container {container_name} failed"));
                self.fail(ctx, msg)
            }
        }
    }

    /// `docker/podman rm -f <name>` — best-effort, errors are logged but not propagated.
    async fn force_remove(&self, ctx: &ToolContext, container_name: &str) {
        let runtime_path = which_runtime(&self.runtime);
        let cleanup_grant = self.grant_issuer.issue_grant(
            &ctx.agent_id,
            ctx.task_id,
            vec![Capability::ProcessExec {
                program: runtime_path.clone(),
                allowed_args_prefix: vec!["rm".to_string()],
                allowed_workdir: std::env::current_dir().unwrap_or_default(),
            }],
            Some(chrono::Duration::minutes(1)),
        );
        let args = vec![
            "rm".to_string(),
            "-f".to_string(),
            container_name.to_string(),
        ];
        let _ = self
            .process_executor
            .execute_process(
                ctx,
                &cleanup_grant,
                &runtime_path,
                &args,
                &std::env::current_dir().unwrap_or_default(),
                Some(10),
            )
            .await;

        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_CONTAINER_CLEANED_UP,
            json!({ "invocation_id": ctx.invocation_id, "container_name": container_name }),
        );
    }

    fn fail(&self, ctx: &ToolContext, message: String) -> ToolResult {
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_CONTAINER_FAILED,
            json!({ "invocation_id": ctx.invocation_id, "error": message }),
        );
        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Failed,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(message),
        }
    }
}

/// Resolve the runtime binary name to a full path if possible, otherwise return the bare name.
fn which_runtime(runtime: &str) -> String {
    // On Windows, `where` is the equivalent of `which`; on Unix, check PATH entries.
    // We keep this simple: if the caller passes an absolute path, use it; otherwise use the bare name
    // and let the OS resolve it. The ProcessExec capability enforces the exact program string.
    runtime.to_string()
}
