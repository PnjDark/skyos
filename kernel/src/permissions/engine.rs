use crate::events::EventBus;
use crate::events::EventError;
use crate::permissions::policy::{AuthorizationOutcome, AuthorizationPolicy, PolicyValidator};
use crate::permissions::types::{
    Capability, CapabilityGrant, PolicyDecision, ToolInvocationRequest,
};
use serde_json::json;
use uuid::Uuid;

pub const EVENT_PERMISSION_GRANTED: &str = "PermissionGranted";
pub const EVENT_PERMISSION_DENIED: &str = "PermissionDenied";
pub const EVENT_CAPABILITIES_AUTHORIZED: &str = "CapabilitiesAuthorized";
pub const EVENT_CAPABILITIES_DENIED: &str = "CapabilitiesDenied";

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
                (
                    ToolInvocationRequest::SystemReconciliation {
                        task_id: req_task, ..
                    },
                    Capability::SystemReconciliation { task_id: cap_task },
                ) => req_task == cap_task,
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

    /// Re-evaluate a whole capability set against the *current* policy.
    ///
    /// This is the Phase 5.2 entry point: a recovery decision is only valid if
    /// the policy in force **now** actually permits the capability intent that
    /// was recorded before the crash.  The decision is audited durably; if the
    /// audit cannot be written the call fails and the caller must fail closed.
    pub fn authorize_capability_set(
        &self,
        policy: &AuthorizationPolicy,
        agent_id: &str,
        task_id: Uuid,
        capabilities: &[Capability],
    ) -> Result<AuthorizationOutcome, EventError> {
        let outcome = policy.authorize(agent_id, capabilities);

        if let Some(bus) = self.event_bus {
            let event_type = if outcome.is_granted() {
                EVENT_CAPABILITIES_AUTHORIZED
            } else {
                EVENT_CAPABILITIES_DENIED
            };
            let payload = match &outcome {
                AuthorizationOutcome::Granted {
                    capabilities,
                    policy_id,
                    policy_version,
                } => json!({
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "decision": "granted",
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "capabilities": capabilities,
                }),
                AuthorizationOutcome::Denied {
                    reason,
                    denied_capability,
                } => json!({
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "decision": "denied",
                    "policy_id": policy.policy_id(),
                    "policy_version": policy.version(),
                    "reason": reason,
                    "denied_capability": denied_capability,
                }),
            };
            bus.emit_event(Some(&task_id.to_string()), event_type, payload)?;
        }

        Ok(outcome)
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
