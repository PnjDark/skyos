use crate::types::{ToolContext, ToolExecutionError, ToolOutput, ToolResult, ToolStatus};
use kernel::artifacts::registry::{ArtifactRegistry, ArtifactType};
use kernel::events::EventBus;
use kernel::permissions::engine::{PolicyEngine, EVENT_PERMISSION_DENIED};
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

pub const DEFAULT_MAX_READ_BYTES: u64 = 10 * 1024 * 1024; // 10MB limit
pub const EVENT_TOOL_EXECUTION_FAILED: &str = "ToolExecutionFailed";
pub const EVENT_TOOL_EXECUTION_COMPLETED: &str = "ToolExecutionCompleted";

pub struct FilesystemToolRegistry<'a> {
    event_bus: &'a EventBus,
    artifact_registry: &'a mut ArtifactRegistry,
    #[allow(dead_code)]
    grant_issuer: &'a GrantIssuer,
}

impl<'a> FilesystemToolRegistry<'a> {
    pub fn new(
        event_bus: &'a EventBus,
        artifact_registry: &'a mut ArtifactRegistry,
        grant_issuer: &'a GrantIssuer,
    ) -> Self {
        Self {
            event_bus,
            artifact_registry,
            grant_issuer,
        }
    }

    /// Resolves nearest existing ancestor to prevent symlink bypasses on missing target chains.
    pub fn validate_and_resolve_path(
        workspace_root: &Path,
        relative_path: &Path,
    ) -> Result<PathBuf, ToolExecutionError> {
        if relative_path.is_absolute() {
            return Err(ToolExecutionError::PathEscape(format!(
                "Absolute paths forbidden: {:?}",
                relative_path
            )));
        }

        for component in relative_path.components() {
            if matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            ) {
                return Err(ToolExecutionError::PathEscape(format!(
                    "Rooted or traversing paths are forbidden: {:?}",
                    relative_path
                )));
            }
        }

        let canonical_workspace = workspace_root.canonicalize().map_err(|e| {
            ToolExecutionError::IoError(format!(
                "Invalid workspace root {:?}: {}",
                workspace_root, e
            ))
        })?;

        let target_path = canonical_workspace.join(relative_path);

        // Find nearest existing ancestor
        let existing_ancestor = Self::nearest_existing_canonical_path(&target_path)?
            .unwrap_or_else(|| canonical_workspace.clone());

        if !existing_ancestor.starts_with(&canonical_workspace) {
            return Err(ToolExecutionError::PathEscape(format!(
                "Path {:?} physically escapes canonical workspace {:?}",
                existing_ancestor, canonical_workspace
            )));
        }

        Ok(target_path)
    }

    fn nearest_existing_canonical_path(path: &Path) -> Result<Option<PathBuf>, ToolExecutionError> {
        let mut current = path;
        loop {
            match std::fs::symlink_metadata(current) {
                Ok(_) => {
                    return current.canonicalize().map(Some).map_err(|error| {
                        ToolExecutionError::PathEscape(format!(
                            "Failed to resolve existing path {:?}: {}",
                            current, error
                        ))
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let Some(parent) = current.parent() else {
                        return Ok(None);
                    };
                    current = parent;
                }
                Err(error) => {
                    return Err(ToolExecutionError::IoError(format!(
                        "Failed to inspect path {:?}: {}",
                        current, error
                    )))
                }
            }
        }
    }

    /// Pre-flight size check before reading file into memory.
    pub fn read_file(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        workspace_root: &Path,
        relative_path: &Path,
        max_bytes: Option<u64>,
    ) -> ToolResult {
        let max_len = max_bytes
            .unwrap_or(DEFAULT_MAX_READ_BYTES)
            .min(DEFAULT_MAX_READ_BYTES);

        let target_path = match Self::validate_and_resolve_path(workspace_root, relative_path) {
            Ok(p) => p,
            Err(e) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    e.to_string(),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        let req = ToolInvocationRequest::FileSystemRead {
            requested_path: target_path.clone(),
        };

        let policy_engine = PolicyEngine::new(Some(self.event_bus));
        let decision = match policy_engine.evaluate_checked(grant, &req) {
            Ok(decision) => decision,
            Err(error) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Failed to persist filesystem read authorization audit: {error}"),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        if !matches!(decision, PolicyDecision::Allow { .. }) {
            return self.record_failure(
                ctx,
                ToolStatus::PermissionDenied,
                format!("Policy Engine denied read access to {:?}", target_path),
                EVENT_PERMISSION_DENIED,
            );
        }

        // Pre-flight metadata check
        let metadata = match std::fs::metadata(&target_path) {
            Ok(m) => m,
            Err(e) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Metadata query failed: {}", e),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        if metadata.len() > max_len {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                format!(
                    "File size {} bytes exceeds maximum allowed limit {}",
                    metadata.len(),
                    max_len
                ),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        // Bounded read stream
        let file = match std::fs::File::open(&target_path) {
            Ok(f) => f,
            Err(e) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Open failure: {}", e),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        let mut handle = file.take(max_len.saturating_add(1));
        let mut buffer = Vec::new();
        match handle.read_to_end(&mut buffer) {
            Ok(read_bytes) => {
                if read_bytes as u64 > max_len {
                    return self.record_failure(
                        ctx,
                        ToolStatus::Failed,
                        format!("File grew during read and exceeded limit {}", max_len),
                        EVENT_TOOL_EXECUTION_FAILED,
                    );
                }

                ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: ToolStatus::Succeeded,
                    output: ToolOutput::Bytes(buffer),
                    artifact: None,
                    error_message: None,
                }
            }
            Err(e) => self.record_failure(
                ctx,
                ToolStatus::Failed,
                format!("Read stream failure: {}", e),
                EVENT_TOOL_EXECUTION_FAILED,
            ),
        }
    }

    /// Atomic write with temporary file staging & auto-rollback on failure.
    pub fn write_file(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        workspace_root: &Path,
        relative_path: &Path,
        content: &[u8],
    ) -> ToolResult {
        let target_path = match Self::validate_and_resolve_path(workspace_root, relative_path) {
            Ok(p) => p,
            Err(e) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    e.to_string(),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        if target_path.file_name().is_none() {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                "A filesystem write requires a file path".to_string(),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        let req = ToolInvocationRequest::FileSystemWrite {
            requested_path: target_path.clone(),
        };

        let policy_engine = PolicyEngine::new(Some(self.event_bus));
        let decision = match policy_engine.evaluate_checked(grant, &req) {
            Ok(decision) => decision,
            Err(error) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Failed to persist filesystem write authorization audit: {error}"),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };

        if !matches!(decision, PolicyDecision::Allow { .. }) {
            return self.record_failure(
                ctx,
                ToolStatus::PermissionDenied,
                format!("Policy Engine denied write access to {:?}", target_path),
                EVENT_PERMISSION_DENIED,
            );
        }

        if let Some(parent) = target_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    format!("Failed directory creation: {}", e),
                    EVENT_TOOL_EXECUTION_FAILED,
                );
            }
        }

        if let Err(error) = Self::validate_and_resolve_path(workspace_root, relative_path) {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                error.to_string(),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        let filename = target_path
            .file_name()
            .expect("validated write path has a file name")
            .to_string_lossy();
        let tmp_path = target_path.with_file_name(format!(".{filename}.{}.tmp", Uuid::new_v4()));
        if let Err(e) = std::fs::write(&tmp_path, content) {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                Self::with_cleanup_error(format!("Temp file write failure: {}", e), &tmp_path),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        let staged_bytes = match std::fs::read(&tmp_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    Self::with_cleanup_error(
                        format!("Failed to verify staged write: {error}"),
                        &tmp_path,
                    ),
                    EVENT_TOOL_EXECUTION_FAILED,
                )
            }
        };
        if staged_bytes != content {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                Self::with_cleanup_error(
                    "Staged file bytes did not match the requested content".to_string(),
                    &tmp_path,
                ),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        let artifact = match self.artifact_registry.register_file_artifact(
            &tmp_path,
            Some(&ctx.task_id.to_string()),
            ArtifactType::Snapshot,
            None,
            json!({
                "invocation_id": ctx.invocation_id,
                "workspace": workspace_root,
                "target_path": target_path,
            }),
        ) {
            Ok(a) => a,
            Err(e) => {
                return self.record_failure(
                    ctx,
                    ToolStatus::Failed,
                    Self::with_cleanup_error(format!("CAS registration failed: {}", e), &tmp_path),
                    EVENT_TOOL_EXECUTION_FAILED,
                );
            }
        };

        if let Err(error) = Self::validate_and_resolve_path(workspace_root, relative_path) {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                Self::with_cleanup_error(error.to_string(), &tmp_path),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        if let Err(e) = std::fs::rename(&tmp_path, &target_path) {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                Self::with_cleanup_error(format!("Atomic rename failed: {}", e), &tmp_path),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        if let Err(error) = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_TOOL_EXECUTION_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "filesystem.write",
                "path": relative_path,
                "artifact_id": artifact.artifact_id,
            }),
        ) {
            return self.record_failure(
                ctx,
                ToolStatus::Failed,
                format!("Filesystem write succeeded but completion audit failed: {error}"),
                EVENT_TOOL_EXECUTION_FAILED,
            );
        }

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Text(format!(
                "Successfully wrote {} bytes to {:?}",
                content.len(),
                relative_path
            )),
            artifact: Some(artifact),
            error_message: None,
        }
    }

    fn with_cleanup_error(mut message: String, path: &Path) -> String {
        match std::fs::remove_file(path) {
            Ok(()) => message,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => message,
            Err(error) => {
                message.push_str(&format!(
                    "; failed to remove staged file {:?}: {error}",
                    path
                ));
                message
            }
        }
    }

    fn record_failure(
        &self,
        ctx: &ToolContext,
        status: ToolStatus,
        msg: String,
        event_type: &str,
    ) -> ToolResult {
        let msg = match self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            event_type,
            json!({
                "invocation_id": ctx.invocation_id,
                "status": status,
                "error": msg
            }),
        ) {
            Ok(_) => msg,
            Err(error) => format!("{msg}; failed to persist audit event: {error}"),
        };

        ToolResult {
            invocation_id: ctx.invocation_id,
            status,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(msg),
        }
    }
}
