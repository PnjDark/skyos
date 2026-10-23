use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Granular capability bounds enforced by the kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    /// Read access constrained to a canonical directory root.
    FileSystemRead { root: PathBuf },
    /// Write access constrained to a canonical directory root.
    FileSystemWrite { root: PathBuf },
    /// Process execution constrained to a binary and allowed argument prefixes.
    ProcessExec {
        program: String,
        allowed_args_prefix: Vec<String>,
        allowed_workdir: PathBuf,
    },
    /// Outbound network request constrained to explicit domains.
    NetworkOutbound { allowed_domain: String },
    /// Execution within an isolated container environment.
    ContainersExec { container_pattern: String },
    /// Read-only Git operations (status, diff, log) within a repository root.
    GitRead { repo_root: PathBuf },
    /// Mutating Git operations (stage, commit, branch, checkout) within a repository root.
    GitWrite { repo_root: PathBuf },
    /// Ephemeral container run constrained to an approved image.
    ContainerRun { allowed_image: String },
    /// Direct hardware device access (camera, serial, lighting).
    /// `device_node` is the exact device path (e.g. `/dev/video0`, `COM3`).
    /// `read_only` prevents write/control operations.
    HardwareAccess {
        device_node: String,
        read_only: bool,
    },
    /// Local network socket binding constrained to a specific address and port ceiling.
    /// `bind_addr` must be a loopback or explicitly authorized subnet address.
    /// `max_port` caps the highest port number the tool may bind.
    NetworkBind { bind_addr: String, max_port: u16 },
    /// Access to a registered domain namespace.
    /// `read_only` prevents mutate() calls.
    DomainAccess { namespace: String, read_only: bool },
}

/// Opaque, kernel‑minted handle representing an authorized execution context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub grant_id: Uuid,
    pub agent_id: String,
    pub task_id: Uuid,
    pub capabilities: Vec<Capability>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

impl CapabilityGrant {
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    // Preserve old name for compatibility
    pub fn is_active(&self) -> bool {
        self.is_valid()
    }
}

/// Structured, normalized tool invocation request presented to the Policy Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolInvocationRequest {
    FileSystemRead {
        requested_path: PathBuf,
    },
    FileSystemWrite {
        requested_path: PathBuf,
    },
    ProcessExec {
        program: String,
        args: Vec<String>,
        workdir: PathBuf,
    },
    NetworkOutbound {
        domain: String,
        url: String,
    },
    ContainerExec {
        container_id: String,
        command: String,
    },
    /// Read-only Git inspection within a repository.
    GitRead {
        repo_root: PathBuf,
    },
    /// Mutating Git operation within a repository.
    GitWrite {
        repo_root: PathBuf,
        operation: String,
    },
    /// Ephemeral container run with a specific image.
    ContainerRun {
        image: String,
    },
    /// Hardware device access request.
    HardwareAccess {
        device_node: String,
        read_only: bool,
    },
    /// Local network socket bind request.
    NetworkBind {
        bind_addr: String,
        port: u16,
    },
    /// Domain namespace access request.
    DomainAccess {
        namespace: String,
        read_only: bool,
    },
}

impl ToolInvocationRequest {
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::FileSystemRead { .. } => "fs.read",
            Self::FileSystemWrite { .. } => "fs.write",
            Self::ProcessExec { .. } => "process.exec",
            Self::NetworkOutbound { .. } => "network.request",
            Self::ContainerExec { .. } => "container.exec",
            Self::GitRead { .. } => "git.read",
            Self::GitWrite { .. } => "git.write",
            Self::ContainerRun { .. } => "container.run",
            Self::HardwareAccess { .. } => "hardware.access",
            Self::NetworkBind { .. } => "network.bind",
            Self::DomainAccess { .. } => "domain.access",
        }
    }
}

/// Explicit, immutable decision produced by the Policy Engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow {
        grant_id: Uuid,
        matched_capability: Capability,
    },
    Deny {
        reason: String,
    },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}
