use crate::events::EventBus;
use crate::events::EventError;
use crate::permissions::policy::PolicyValidator;
use crate::permissions::types::{
    Capability, CapabilityGrant, PolicyDecision, ToolInvocationRequest,
};
use serde_json::json;

pub const EVENT_PERMISSION_GRANTED: &str = "PermissionGranted";
pub const EVENT_PERMISSION_DENIED: &str = "PermissionDenied";

pub struct PolicyEngine<'a> {
    event_bus: Option<&'a EventBus>,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(event_bus: Option<&'a EventBus>) -> Self {
        Self { event_bus }
    }

    /// Evaluates a tool invocation request against a grant and emits a durable audit event.
    pub fn evaluate(
        &self,
        grant: &CapabilityGrant,
        request: &ToolInvocationRequest,
    ) -> PolicyDecision {
        self.evaluate_checked(grant, request)
            .unwrap_or_else(|error| PolicyDecision::Deny {
                reason: format!("Failed to persist policy audit event: {error}"),
            })
    }

    /// Evaluates a request and returns an error if its decision cannot be durably audited.
    pub fn evaluate_checked(
        &self,
        grant: &CapabilityGrant,
        request: &ToolInvocationRequest,
    ) -> Result<PolicyDecision, EventError> {
        // 1. Check grant lifetime and revocation status
        if !grant.is_active() {
            let decision = PolicyDecision::Deny {
                reason: format!("Capability grant {} is expired or revoked", grant.grant_id),
            };
            self.audit_log(grant, request, &decision)?;
            return Ok(decision);
        }

        // 2. Evaluate capability match
        let mut matched_capability: Option<Capability> = None;
        for cap in &grant.capabilities {
            let matches = match (request, cap) {
                (
                    ToolInvocationRequest::FileSystemRead { requested_path },
                    Capability::FileSystemRead { root },
                ) => PolicyValidator::validate_fs_access(requested_path, root),
                (
                    ToolInvocationRequest::FileSystemWrite { requested_path },
                    Capability::FileSystemWrite { root },
                ) => PolicyValidator::validate_fs_access(requested_path, root),
                (
                    ToolInvocationRequest::ProcessExec {
                        program,
                        args,
                        workdir,
                    },
                    Capability::ProcessExec {
                        program: cap_prog,
                        allowed_args_prefix,
                        allowed_workdir,
                    },
                ) => PolicyValidator::validate_process_exec(
                    program,
                    args,
                    workdir,
                    cap_prog,
                    allowed_args_prefix,
                    allowed_workdir,
                ),
                (
                    ToolInvocationRequest::NetworkOutbound { domain, .. },
                    Capability::NetworkOutbound { allowed_domain },
                ) => allowed_domain == "*" || allowed_domain == domain,
                (
                    ToolInvocationRequest::ContainerExec { container_id, .. },
                    Capability::ContainersExec { container_pattern },
                ) => container_pattern == "*" || container_pattern == container_id,
                (
                    ToolInvocationRequest::GitRead {
                        repo_root: requested_root,
                    },
                    Capability::GitRead { repo_root },
                ) => PolicyValidator::validate_fs_access(requested_root, repo_root),
                (
                    ToolInvocationRequest::GitWrite {
                        repo_root: requested_root,
                        ..
                    },
                    Capability::GitWrite { repo_root },
                ) => PolicyValidator::validate_fs_access(requested_root, repo_root),
                // GitRead grant also covers GitRead requests (read-only subset)
                (
                    ToolInvocationRequest::GitRead {
                        repo_root: requested_root,
                    },
                    Capability::GitWrite { repo_root },
                ) => PolicyValidator::validate_fs_access(requested_root, repo_root),
                (
                    ToolInvocationRequest::ContainerRun { image },
                    Capability::ContainerRun { allowed_image },
                ) => allowed_image == "*" || allowed_image == image,
                (
                    ToolInvocationRequest::HardwareAccess {
                        device_node: req_node,
                        read_only: req_ro,
                    },
                    Capability::HardwareAccess {
                        device_node: cap_node,
                        read_only: cap_ro,
                    },
                ) => {
                    // Device node must match exactly.
                    // A read-only capability cannot satisfy a write (read_only=false) request.
                    req_node == cap_node && (*req_ro || !cap_ro)
                }
                (
                    ToolInvocationRequest::NetworkBind {
                        bind_addr: req_addr,
                        port: req_port,
                    },
                    Capability::NetworkBind {
                        bind_addr: cap_addr,
                        max_port,
                    },
                ) => req_addr == cap_addr && req_port <= max_port,
                (
                    ToolInvocationRequest::DomainAccess {
                        namespace: req_ns,
                        read_only: req_ro,
                    },
                    Capability::DomainAccess {
                        namespace: cap_ns,
                        read_only: cap_ro,
                    },
                ) => req_ns == cap_ns && (*req_ro || !cap_ro),
                _ => false,
            };
            if matches {
                matched_capability = Some(cap.clone());
                break;
            }
        }

        let decision = match matched_capability {
            Some(cap) => PolicyDecision::Allow {
                grant_id: grant.grant_id,
                matched_capability: cap,
            },
            None => PolicyDecision::Deny {
                reason: format!(
                    "No matching capability for tool '{}' in grant {}",
                    request.tool_name(),
                    grant.grant_id
                ),
            },
        };

        // 3. Emit durable audit event
        self.audit_log(grant, request, &decision)?;
        Ok(decision)
    }

    fn audit_log(
        &self,
        grant: &CapabilityGrant,
        request: &ToolInvocationRequest,
        decision: &PolicyDecision,
    ) -> Result<(), EventError> {
        if let Some(bus) = self.event_bus {
            let event_type = if decision.is_allowed() {
                EVENT_PERMISSION_GRANTED
            } else {
                EVENT_PERMISSION_DENIED
            };
            let payload = json!({
                "grant_id": grant.grant_id,
                "agent_id": grant.agent_id,
                "task_id": grant.task_id,
                "tool": request.tool_name(),
                "request": request,
                "decision": decision
            });
            bus.emit_event(Some(&grant.task_id.to_string()), event_type, payload)?;
        }
        Ok(())
    }
}
