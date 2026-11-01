use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

pub const DEFAULT_PROCESS_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 100 * 1024;
pub const EVENT_PROCESS_FAILED: &str = "ProcessExecutionFailed";
pub const EVENT_PROCESS_COMPLETED: &str = "ProcessExecutionCompleted";

pub struct ProcessToolExecutor<'a> {
    event_bus: &'a EventBus,
    #[allow(dead_code)]
    grant_issuer: &'a GrantIssuer,
}

impl<'a> ProcessToolExecutor<'a> {
    pub fn new(event_bus: &'a EventBus, grant_issuer: &'a GrantIssuer) -> Self {
        Self {
            event_bus,
            grant_issuer,
        }
    }

    pub async fn execute_process(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        program: &str,
        args: &[String],
        workdir: &Path,
        timeout_secs: Option<u64>,
    ) -> ToolResult {
        let timeout_duration =
            Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_PROCESS_TIMEOUT_SECS));
        let request = ToolInvocationRequest::ProcessExec {
            program: program.to_string(),
            args: args.to_vec(),
            workdir: workdir.to_path_buf(),
        };
        let policy_engine = PolicyEngine::new(Some(self.event_bus));
        let decision = match policy_engine.evaluate_checked(grant, &request) {
            Ok(decision) => decision,
            Err(error) => {
                return self.record_process_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Failed to persist process authorization audit: {error}"),
                )
            }
        };

        if !matches!(decision, PolicyDecision::Allow { .. }) {
            return self.record_process_failure(
                ctx,
                ToolStatus::PermissionDenied,
                format!("Policy Engine denied process execution: {program}"),
            );
        }

        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return self.record_process_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Failed to spawn {program}: {error}"),
                )
            }
        };

        let Some(stdout) = child.stdout.take() else {
            return self
                .terminate_and_fail(
                    ctx,
                    &mut child,
                    ToolStatus::Failed,
                    "Spawned process did not provide a stdout pipe".to_string(),
                )
                .await;
        };
        let Some(stderr) = child.stderr.take() else {
            return self
                .terminate_and_fail(
                    ctx,
                    &mut child,
                    ToolStatus::Failed,
                    "Spawned process did not provide a stderr pipe".to_string(),
                )
                .await;
        };

        let mut stdout_reader = tokio::spawn(read_bounded(stdout, DEFAULT_MAX_OUTPUT_BYTES));
        let mut stderr_reader = tokio::spawn(read_bounded(stderr, DEFAULT_MAX_OUTPUT_BYTES));
        let execution = async {
            let status = child.wait().await;
            let (stdout, stderr) = tokio::join!(&mut stdout_reader, &mut stderr_reader);
            (status, stdout, stderr)
        };

        match tokio::time::timeout(timeout_duration, execution).await {
            Ok((status, stdout, stderr)) => {
                let status = match status {
                    Ok(status) => status,
                    Err(error) => {
                        return self.record_process_failure(
                            ctx,
                            ToolStatus::Failed,
                            format!("Failed waiting for process {program}: {error}"),
                        )
                    }
                };
                let stdout = match stdout {
                    Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
                    Ok(Err(error)) => {
                        return self.record_process_failure(
                            ctx,
                            ToolStatus::Failed,
                            format!("Failed reading process stdout: {error}"),
                        )
                    }
                    Err(error) => {
                        return self.record_process_failure(
                            ctx,
                            ToolStatus::Failed,
                            format!("Process stdout reader failed: {error}"),
                        )
                    }
                };
                let stderr = match stderr {
                    Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
                    Ok(Err(error)) => {
                        return self.record_process_failure(
                            ctx,
                            ToolStatus::Failed,
                            format!("Failed reading process stderr: {error}"),
                        )
                    }
                    Err(error) => {
                        return self.record_process_failure(
                            ctx,
                            ToolStatus::Failed,
                            format!("Process stderr reader failed: {error}"),
                        )
                    }
                };
                let exit_code = status.code().unwrap_or(-1);
                let tool_status = if status.success() {
                    ToolStatus::Succeeded
                } else {
                    ToolStatus::OutcomeUnknown
                };
                let error_message = (!status.success()).then(|| {
                    format!(
                        "Process exited with code {exit_code}; its side effects require reconciliation"
                    )
                });
                if let Err(error) = self.event_bus.emit_event(
                    Some(&ctx.task_id.to_string()),
                    EVENT_PROCESS_COMPLETED,
                    json!({
                        "invocation_id": ctx.invocation_id,
                        "program": program,
                        "exit_code": exit_code,
                        "status": tool_status,
                    }),
                ) {
                    return self.record_process_failure(
                        ctx,
                        ToolStatus::AuditPersistenceFailed,
                        format!("Process completed but completion audit failed: {error}"),
                    );
                }
                ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: tool_status,
                    output: ToolOutput::ProcessResult {
                        exit_code,
                        stdout,
                        stderr,
                    },
                    artifact: None,
                    error_message,
                }
            }
            Err(_) => {
                let kill_result = child.start_kill();
                let reap_result = child.wait().await;
                stdout_reader.abort();
                stderr_reader.abort();
                let message = match (kill_result, reap_result) {
                    (Ok(()), Ok(_)) => format!(
                        "Process {program} timed out after {} seconds and was killed and reaped",
                        timeout_duration.as_secs()
                    ),
                    (Err(kill_error), Ok(_)) => format!(
                        "Process {program} timed out; kill request failed ({kill_error}), \
                         but the process was reaped"
                    ),
                    (_, Err(wait_error)) => {
                        format!("Process {program} timed out but could not be reaped: {wait_error}")
                    }
                };
                self.record_process_failure(ctx, ToolStatus::TimedOut, message)
            }
        }
    }

    async fn terminate_and_fail(
        &self,
        ctx: &ToolContext,
        child: &mut Child,
        status: ToolStatus,
        mut message: String,
    ) -> ToolResult {
        if let Err(error) = child.start_kill() {
            message.push_str(&format!("; failed to kill spawned process: {error}"));
        }
        if let Err(error) = child.wait().await {
            message.push_str(&format!("; failed to reap spawned process: {error}"));
        }
        self.record_process_failure(ctx, status, message)
    }

    fn record_process_failure(
        &self,
        ctx: &ToolContext,
        status: ToolStatus,
        mut message: String,
    ) -> ToolResult {
        if let Err(error) = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_PROCESS_FAILED,
            json!({"invocation_id": ctx.invocation_id, "status": status, "error": message}),
        ) {
            message.push_str(&format!("; failed to persist failure audit event: {error}"));
        }
        ToolResult {
            invocation_id: ctx.invocation_id,
            status,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(message),
        }
    }
}

async fn read_bounded<R>(mut reader: R, limit: usize) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut chunk = [0_u8; 8192];
    loop {
        let bytes_read = reader.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Ok(output);
        }
        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..bytes_read.min(remaining)]);
    }
}
