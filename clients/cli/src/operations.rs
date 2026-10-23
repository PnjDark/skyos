use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Typed, deterministic operations that Sky CLI can authorize and execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationSpec {
    /// Writes a deterministic snapshot file into the authorized workspace.
    WriteSnapshot {
        relative_path: PathBuf,
        content_bytes: Vec<u8>,
    },
}

impl OperationSpec {
    pub fn operation_type(&self) -> &'static str {
        match self {
            Self::WriteSnapshot { .. } => "WriteSnapshot",
        }
    }
}
