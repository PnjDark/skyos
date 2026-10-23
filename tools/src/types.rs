use kernel::artifacts::registry::Artifact;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContext {
    pub invocation_id: Uuid,
    pub task_id: Uuid,
    pub agent_id: String,
}

impl ToolContext {
    pub fn new(task_id: Uuid, agent_id: impl Into<String>) -> Self {
        Self {
            invocation_id: Uuid::new_v4(),
            task_id,
            agent_id: agent_id.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolStatus {
    Succeeded,
    Failed,
    PermissionDenied,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolOutput {
    Empty,
    Text(String),
    Bytes(Vec<u8>),
    DirectoryListing(Vec<String>),
    ProcessResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub invocation_id: Uuid,
    pub status: ToolStatus,
    pub output: ToolOutput,
    pub artifact: Option<Artifact>,
    pub error_message: Option<String>,
}

#[derive(Error, Debug)]
pub enum ToolExecutionError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Path traversal or symlink escape detected: {0}")]
    PathEscape(String),
    #[error("I/O boundary failure: {0}")]
    IoError(String),
    #[error("Process execution timed out after {0} seconds")]
    Timeout(u64),
    #[error("Audit log emission failed: {0}")]
    AuditFailed(String),
}
