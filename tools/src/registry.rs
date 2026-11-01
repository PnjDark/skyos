use crate::containers::{ContainerLimits, ContainerToolExecutor};
use crate::domain::DomainToolExecutor;
use crate::filesystem::FilesystemToolRegistry;
use crate::git::GitToolRegistry;
use crate::hardware::HardwareToolExecutor;
use crate::network::NetworkToolExecutor;
use crate::process::ProcessToolExecutor;
use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::artifacts::registry::ArtifactRegistry;
use kernel::domain::DomainStore;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, CapabilityKind};
use kernel::tasks::checkpoint::SideEffectSemantics;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use thiserror::Error;

// ── Public request / schema types ────────────────────────────────────────────

/// A single tool invocation submitted to the dispatcher.
///
/// `idempotency_key` is an optional caller-supplied token that Phase 5 crash
/// recovery uses to distinguish a retried invocation from a new one.  When
/// absent the dispatcher falls back to `ctx.invocation_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationRequest {
    pub tool_id: String,
    pub operation_id: String,
    pub parameters: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Machine-readable description of one registered operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub tool_id: String,
    pub operation_id: String,
    pub description: String,
    pub required_capability: String,
    pub parameters_schema: Value,
}

/// Distinct failure codes returned by the dispatcher before tool execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Error)]
pub enum DispatchError {
    #[error("Unknown tool_id: {0}")]
    UnknownTool(String),
    #[error("Unknown operation '{0}' for tool '{1}'")]
    UnknownOperation(String, String),
    #[error("Missing required parameter '{0}'")]
    MissingParameter(String),
    #[error("Invalid parameter type for '{0}': {1}")]
    InvalidParameter(String, String),
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

pub struct UnifiedToolRegistry<'a> {
    event_bus: &'a EventBus,
    artifact_registry: &'a mut ArtifactRegistry,
    grant_issuer: &'a GrantIssuer,
    domain_store: Option<&'a DomainStore>,
}

impl<'a> UnifiedToolRegistry<'a> {
    pub fn new(
        event_bus: &'a EventBus,
        artifact_registry: &'a mut ArtifactRegistry,
        grant_issuer: &'a GrantIssuer,
    ) -> Self {
        Self {
            event_bus,
            artifact_registry,
            grant_issuer,
            domain_store: None,
        }
    }

    pub fn with_domain_store(mut self, store: &'a DomainStore) -> Self {
        self.domain_store = Some(store);
        self
    }

    /// Return the runtime-owned retry contract for an operation. Unknown
    /// operations default to AtMostOnce so recovery never retries them blindly.
    pub fn side_effect_semantics(tool_id: &str, operation_id: &str) -> SideEffectSemantics {
        match (tool_id, operation_id) {
            ("filesystem", "read_file")
            | ("git", "status" | "diff" | "log")
            | ("domain", "query")
            | ("hardware", "capture_frame") => SideEffectSemantics::Idempotent,
            ("filesystem", "write_file")
            | ("git", "stage" | "commit" | "branch_create" | "checkout")
            | ("domain", "mutate")
            | ("network", "bind_socket") => SideEffectSemantics::Reconcilable,
            ("process", "execute")
            | ("container", "run")
            | ("hardware", "serial_write")
            | ("network", "send_datagram") => SideEffectSemantics::AtMostOnce,
            _ => SideEffectSemantics::AtMostOnce,
        }
    }

    /// Return the capability family a registered operation requires.
    ///
    /// This is derived from the tool manifest, not from anything the agent
    /// says.  Recovery uses it to narrow a persisted capability intent down to
    /// the authority the pending operation actually needs; an operation whose
    /// requirement cannot be derived is never re-authorized.
    pub fn required_capability_kind(tool_id: &str, operation_id: &str) -> Option<CapabilityKind> {
        Self::export_schemas()
            .into_iter()
            .find(|schema| schema.tool_id == tool_id && schema.operation_id == operation_id)
            .and_then(|schema| CapabilityKind::from_name(&schema.required_capability))
    }

    /// Primary entry point.
    ///
    /// Validates the request schema, then delegates authorization and execution
    /// to the appropriate tool. The underlying `PolicyEngine` is always invoked —
    /// this dispatcher never substitutes its own permission check.
    pub async fn dispatch(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        request: InvocationRequest,
        workspace_root: &Path,
    ) -> ToolResult {
        let idempotency_key = request
            .idempotency_key
            .clone()
            .unwrap_or_else(|| ctx.invocation_id.to_string());

        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            "ToolInvocationAttempted",
            serde_json::json!({
                "invocation_id": ctx.invocation_id,
                "agent_id": ctx.agent_id,
                "tool_id": request.tool_id,
                "operation_id": request.operation_id,
                "idempotency_key": idempotency_key,
                "grant_id": grant.grant_id,
            }),
        );

        match request.tool_id.as_str() {
            "filesystem" => self.dispatch_filesystem(
                ctx,
                grant,
                &request.operation_id,
                &request.parameters,
                workspace_root,
            ),
            "process" => {
                self.dispatch_process(
                    ctx,
                    grant,
                    &request.operation_id,
                    &request.parameters,
                    workspace_root,
                )
                .await
            }
            "git" => {
                self.dispatch_git(
                    ctx,
                    grant,
                    &request.operation_id,
                    &request.parameters,
                    workspace_root,
                )
                .await
            }
            "container" => {
                self.dispatch_container(
                    ctx,
                    grant,
                    &request.operation_id,
                    &request.parameters,
                    workspace_root,
                )
                .await
            }
            "hardware" => {
                self.dispatch_hardware(ctx, grant, &request.operation_id, &request.parameters)
            }
            "network" => {
                self.dispatch_network(ctx, grant, &request.operation_id, &request.parameters)
            }
            "domain" => {
                self.dispatch_domain(ctx, grant, &request.operation_id, &request.parameters)
            }
            unknown => self.dispatch_error(ctx, DispatchError::UnknownTool(unknown.to_string())),
        }
    }

    /// Export machine-readable schemas for all registered operations.
    ///
    /// Schemas describe accepted arguments and required capability names only.
    /// They never expose grant secrets, internal permission state, or runtime paths.
    pub fn export_schemas() -> Vec<ToolSchema> {
        vec![
            ToolSchema {
                tool_id: "filesystem".into(),
                operation_id: "read_file".into(),
                description: "Read file contents bounded by the authorized workspace root.".into(),
                required_capability: "FileSystemRead".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "relative_path": { "type": "string", "description": "Path relative to workspace root." },
                        "max_bytes": { "type": "integer", "description": "Optional read limit (max 10 MB)." }
                    },
                    "required": ["relative_path"]
                }),
            },
            ToolSchema {
                tool_id: "filesystem".into(),
                operation_id: "write_file".into(),
                description: "Atomically write file bytes with CAS artifact proof.".into(),
                required_capability: "FileSystemWrite".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "relative_path": { "type": "string" },
                        "content": { "type": "string", "description": "UTF-8 file content." }
                    },
                    "required": ["relative_path", "content"]
                }),
            },
            ToolSchema {
                tool_id: "process".into(),
                operation_id: "execute".into(),
                description: "Execute a program directly with bounded streaming output.".into(),
                required_capability: "ProcessExec".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "program": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } },
                        "timeout_secs": { "type": "integer" }
                    },
                    "required": ["program", "args"]
                }),
            },
            ToolSchema {
                tool_id: "git".into(),
                operation_id: "status".into(),
                description: "Run git status --porcelain within the authorized repository.".into(),
                required_capability: "GitRead".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            },
            ToolSchema {
                tool_id: "git".into(),
                operation_id: "diff".into(),
                description:
                    "Run git diff (or git diff --cached) within the authorized repository.".into(),
                required_capability: "GitRead".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "cached": { "type": "boolean", "description": "If true, diff staged changes." }
                    },
                    "required": []
                }),
            },
            ToolSchema {
                tool_id: "git".into(),
                operation_id: "log".into(),
                description: "Run git log --oneline within the authorized repository.".into(),
                required_capability: "GitRead".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "description": "Maximum number of commits (default 20)." }
                    },
                    "required": []
                }),
            },
            ToolSchema {
                tool_id: "git".into(),
                operation_id: "stage".into(),
                description: "Stage explicitly listed relative paths (git add -- <paths>).".into(),
                required_capability: "GitWrite".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Relative paths to stage. No traversal or absolute paths."
                        }
                    },
                    "required": ["paths"]
                }),
            },
            ToolSchema {
                tool_id: "git".into(),
                operation_id: "commit".into(),
                description: "Commit staged changes and register a Diff artifact.".into(),
                required_capability: "GitWrite".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "message": { "type": "string" }
                    },
                    "required": ["message"]
                }),
            },
            ToolSchema {
                tool_id: "container".into(),
                operation_id: "run".into(),
                description:
                    "Run an ephemeral container with strict isolation and resource limits.".into(),
                required_capability: "ContainerRun".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "image": { "type": "string" },
                        "command": { "type": "array", "items": { "type": "string" } },
                        "cpus": { "type": "number" },
                        "memory_mb": { "type": "integer" },
                        "timeout_secs": { "type": "integer" }
                    },
                    "required": ["image", "command"]
                }),
            },
            ToolSchema {
                tool_id: "hardware".into(),
                operation_id: "capture_frame".into(),
                description: "Capture a single frame from a camera device with CAS artifact proof."
                    .into(),
                required_capability: "HardwareAccess".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "device_node": { "type": "string", "description": "Device path (e.g. /dev/video0, COM3)." },
                        "max_bytes": { "type": "integer", "description": "Optional frame size cap (max 4 MB)." }
                    },
                    "required": ["device_node"]
                }),
            },
            ToolSchema {
                tool_id: "hardware".into(),
                operation_id: "serial_write".into(),
                description: "Send a control payload to a serial/USB device.".into(),
                required_capability: "HardwareAccess".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "device_node": { "type": "string" },
                        "baud_rate": { "type": "integer", "description": "Standard baud rate (e.g. 115200)." },
                        "payload_hex": { "type": "string", "description": "Hex-encoded bytes to write." }
                    },
                    "required": ["device_node", "baud_rate", "payload_hex"]
                }),
            },
            ToolSchema {
                tool_id: "network".into(),
                operation_id: "bind_socket".into(),
                description:
                    "Bind a local TCP/UDP socket restricted to loopback or private subnet.".into(),
                required_capability: "NetworkBind".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "bind_addr": { "type": "string", "description": "Loopback or RFC-1918 address." },
                        "port": { "type": "integer", "description": "Port >= 1024." }
                    },
                    "required": ["bind_addr", "port"]
                }),
            },
            ToolSchema {
                tool_id: "network".into(),
                operation_id: "send_datagram".into(),
                description: "Send a bounded datagram to a local socket address.".into(),
                required_capability: "NetworkBind".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "dest_addr": { "type": "string" },
                        "port": { "type": "integer" },
                        "payload_hex": { "type": "string", "description": "Hex-encoded payload (max 64 KB)." }
                    },
                    "required": ["dest_addr", "port", "payload_hex"]
                }),
            },
            ToolSchema {
                tool_id: "domain".into(),
                operation_id: "query".into(),
                description: "Execute a SELECT query against a registered domain namespace.".into(),
                required_capability: "DomainAccess".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "namespace": { "type": "string", "description": "Registered domain namespace (e.g. fitness, pantry)." },
                        "sql": { "type": "string", "description": "SELECT statement with ? placeholders." },
                        "params": { "type": "array", "description": "Positional parameter values." }
                    },
                    "required": ["namespace", "sql"]
                }),
            },
            ToolSchema {
                tool_id: "domain".into(),
                operation_id: "mutate".into(),
                description:
                    "Execute an INSERT/UPDATE/DELETE against a registered domain namespace.".into(),
                required_capability: "DomainAccess".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "namespace": { "type": "string" },
                        "sql": { "type": "string", "description": "INSERT/UPDATE/DELETE with ? placeholders." },
                        "params": { "type": "array" }
                    },
                    "required": ["namespace", "sql"]
                }),
            },
        ]
    }

    // ── filesystem ────────────────────────────────────────────────────────────

    fn dispatch_filesystem(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
        workspace_root: &Path,
    ) -> ToolResult {
        match op {
            "read_file" => {
                let relative_path = match require_str(params, "relative_path") {
                    Ok(p) => p,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let max_bytes = params.get("max_bytes").and_then(Value::as_u64);
                let fs = FilesystemToolRegistry::new(
                    self.event_bus,
                    self.artifact_registry,
                    self.grant_issuer,
                );
                fs.read_file(
                    ctx,
                    grant,
                    workspace_root,
                    Path::new(relative_path),
                    max_bytes,
                )
            }
            "write_file" => {
                let relative_path = match require_str(params, "relative_path") {
                    Ok(p) => p,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let content = match require_str(params, "content") {
                    Ok(c) => c,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let mut fs = FilesystemToolRegistry::new(
                    self.event_bus,
                    self.artifact_registry,
                    self.grant_issuer,
                );
                fs.write_file(
                    ctx,
                    grant,
                    workspace_root,
                    Path::new(relative_path),
                    content.as_bytes(),
                )
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "filesystem".to_string()),
            ),
        }
    }

    // ── process ───────────────────────────────────────────────────────────────

    async fn dispatch_process(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
        workspace_root: &Path,
    ) -> ToolResult {
        match op {
            "execute" => {
                let program = match require_str(params, "program") {
                    Ok(p) => p,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let args = match require_str_array(params, "args") {
                    Ok(a) => a,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let timeout_secs = params.get("timeout_secs").and_then(Value::as_u64);
                let executor = ProcessToolExecutor::new(self.event_bus, self.grant_issuer);
                executor
                    .execute_process(ctx, grant, program, &args, workspace_root, timeout_secs)
                    .await
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "process".to_string()),
            ),
        }
    }

    // ── git ───────────────────────────────────────────────────────────────────

    async fn dispatch_git(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
        repo_root: &Path,
    ) -> ToolResult {
        match op {
            "status" => {
                let git =
                    GitToolRegistry::new(self.event_bus, self.artifact_registry, self.grant_issuer);
                git.status(ctx, grant, repo_root).await
            }
            "diff" => {
                let cached = params
                    .get("cached")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let git =
                    GitToolRegistry::new(self.event_bus, self.artifact_registry, self.grant_issuer);
                git.diff(ctx, grant, repo_root, cached).await
            }
            "log" => {
                let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(20) as u32;
                let git =
                    GitToolRegistry::new(self.event_bus, self.artifact_registry, self.grant_issuer);
                git.log(ctx, grant, repo_root, limit).await
            }
            "stage" => {
                let raw_paths = match require_str_array(params, "paths") {
                    Ok(p) => p,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let path_refs: Vec<&str> = raw_paths.iter().map(String::as_str).collect();
                let git =
                    GitToolRegistry::new(self.event_bus, self.artifact_registry, self.grant_issuer);
                git.stage(ctx, grant, repo_root, &path_refs).await
            }
            "commit" => {
                let message = match require_str(params, "message") {
                    Ok(m) => m,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let mut git =
                    GitToolRegistry::new(self.event_bus, self.artifact_registry, self.grant_issuer);
                git.commit(ctx, grant, repo_root, message).await
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "git".to_string()),
            ),
        }
    }

    // ── container ─────────────────────────────────────────────────────────────

    async fn dispatch_container(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
        _workspace_root: &Path,
    ) -> ToolResult {
        match op {
            "run" => {
                let image = match require_str(params, "image") {
                    Ok(i) => i,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let raw_cmd = match require_str_array(params, "command") {
                    Ok(c) => c,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let cmd_refs: Vec<&str> = raw_cmd.iter().map(String::as_str).collect();

                let limits = ContainerLimits {
                    cpus: params
                        .get("cpus")
                        .and_then(Value::as_f64)
                        .map(|v| v as f32)
                        .unwrap_or(1.0),
                    memory_mb: params
                        .get("memory_mb")
                        .and_then(Value::as_u64)
                        .unwrap_or(512),
                    timeout_secs: params
                        .get("timeout_secs")
                        .and_then(Value::as_u64)
                        .unwrap_or(60),
                    ..ContainerLimits::default()
                };

                let executor =
                    ContainerToolExecutor::new(self.event_bus, self.grant_issuer, "docker");
                executor
                    .run(ctx, grant, image, &cmd_refs, None, Some(limits))
                    .await
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "container".to_string()),
            ),
        }
    }

    // ── domain ───────────────────────────────────────────────────────────────

    fn dispatch_domain(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
    ) -> ToolResult {
        let store = match self.domain_store {
            Some(s) => s,
            None => {
                return ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: ToolStatus::Failed,
                    output: ToolOutput::Empty,
                    artifact: None,
                    error_message: Some(
                        "Domain store not configured in this dispatcher".to_string(),
                    ),
                }
            }
        };
        let namespace = match require_str(params, "namespace") {
            Ok(n) => n,
            Err(e) => return self.dispatch_error(ctx, e),
        };
        let sql = match require_str(params, "sql") {
            Ok(s) => s,
            Err(e) => return self.dispatch_error(ctx, e),
        };
        let query_params: Vec<serde_json::Value> = params
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let executor = DomainToolExecutor::new(self.event_bus, store, self.grant_issuer);
        match op {
            "query" => executor.query(ctx, grant, namespace, sql, query_params),
            "mutate" => executor.mutate(ctx, grant, namespace, sql, query_params),
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "domain".to_string()),
            ),
        }
    }

    // ── hardware ──────────────────────────────────────────────────────────────

    fn dispatch_hardware(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
    ) -> ToolResult {
        match op {
            "capture_frame" => {
                let device_node = match require_str(params, "device_node") {
                    Ok(d) => d,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let max_bytes = params
                    .get("max_bytes")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize);
                let mut hw = HardwareToolExecutor::new(
                    self.event_bus,
                    self.artifact_registry,
                    self.grant_issuer,
                );
                hw.capture_frame(ctx, grant, device_node, max_bytes)
            }
            "serial_write" => {
                let device_node = match require_str(params, "device_node") {
                    Ok(d) => d,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let baud_rate = match params.get("baud_rate").and_then(Value::as_u64) {
                    Some(b) => b as u32,
                    None => {
                        return self.dispatch_error(
                            ctx,
                            DispatchError::MissingParameter("baud_rate".into()),
                        )
                    }
                };
                let payload_hex = match require_str(params, "payload_hex") {
                    Ok(h) => h,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let payload = match hex::decode(payload_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return self.dispatch_error(
                            ctx,
                            DispatchError::InvalidParameter("payload_hex".into(), e.to_string()),
                        )
                    }
                };
                let mut hw = HardwareToolExecutor::new(
                    self.event_bus,
                    self.artifact_registry,
                    self.grant_issuer,
                );
                hw.serial_write(ctx, grant, device_node, baud_rate, &payload)
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "hardware".to_string()),
            ),
        }
    }

    // ── network ───────────────────────────────────────────────────────────────

    fn dispatch_network(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        op: &str,
        params: &Value,
    ) -> ToolResult {
        match op {
            "bind_socket" => {
                let bind_addr = match require_str(params, "bind_addr") {
                    Ok(a) => a,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let port = match params.get("port").and_then(Value::as_u64) {
                    Some(p) if p <= u16::MAX as u64 => p as u16,
                    _ => {
                        return self
                            .dispatch_error(ctx, DispatchError::MissingParameter("port".into()))
                    }
                };
                let net = NetworkToolExecutor::new(self.event_bus, self.grant_issuer);
                net.bind_socket(ctx, grant, bind_addr, port)
            }
            "send_datagram" => {
                let dest_addr = match require_str(params, "dest_addr") {
                    Ok(a) => a,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let port = match params.get("port").and_then(Value::as_u64) {
                    Some(p) if p <= u16::MAX as u64 => p as u16,
                    _ => {
                        return self
                            .dispatch_error(ctx, DispatchError::MissingParameter("port".into()))
                    }
                };
                let payload_hex = match require_str(params, "payload_hex") {
                    Ok(h) => h,
                    Err(e) => return self.dispatch_error(ctx, e),
                };
                let payload = match hex::decode(payload_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return self.dispatch_error(
                            ctx,
                            DispatchError::InvalidParameter("payload_hex".into(), e.to_string()),
                        )
                    }
                };
                let net = NetworkToolExecutor::new(self.event_bus, self.grant_issuer);
                net.send_datagram(ctx, grant, dest_addr, port, &payload)
            }
            unknown => self.dispatch_error(
                ctx,
                DispatchError::UnknownOperation(unknown.to_string(), "network".to_string()),
            ),
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn dispatch_error(&self, ctx: &ToolContext, error: DispatchError) -> ToolResult {
        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Failed,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(error.to_string()),
        }
    }
}

// ── parameter extraction helpers ─────────────────────────────────────────────

fn require_str<'v>(params: &'v Value, key: &str) -> Result<&'v str, DispatchError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DispatchError::MissingParameter(key.to_string()))
}

fn require_str_array(params: &Value, key: &str) -> Result<Vec<String>, DispatchError> {
    let arr = params
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| DispatchError::MissingParameter(key.to_string()))?;

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str().map(str::to_owned).ok_or_else(|| {
                DispatchError::InvalidParameter(
                    key.to_string(),
                    format!("element {i} is not a string"),
                )
            })
        })
        .collect()
}
