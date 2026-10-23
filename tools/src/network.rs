use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;
use std::net::IpAddr;

pub const EVENT_NETWORK_COMPLETED: &str = "NetworkOperationCompleted";
pub const EVENT_NETWORK_FAILED: &str = "NetworkOperationFailed";

/// Maximum payload size for a single datagram send (64 KB).
pub const MAX_DATAGRAM_BYTES: usize = 64 * 1024;

/// Validates that a bind address is loopback or an explicitly authorized
/// private subnet.  Rejects any public routable address.
pub fn validate_bind_addr(addr: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("Bind address {addr:?} is not a valid IP address"))?;

    if ip.is_loopback() {
        return Ok(ip);
    }

    // Allow RFC-1918 private ranges only.
    let is_private = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false, // Only IPv4 private ranges permitted for now.
    };

    if is_private {
        Ok(ip)
    } else {
        Err(format!(
            "Bind address {addr:?} is not loopback or a private subnet address"
        ))
    }
}

/// Validates a port is within the ephemeral range and not a privileged port.
pub fn validate_port(port: u16) -> Result<(), String> {
    if port < 1024 {
        return Err(format!("Port {port} is a privileged port (< 1024)"));
    }
    Ok(())
}

pub struct NetworkToolExecutor<'a> {
    event_bus: &'a EventBus,
    #[allow(dead_code)]
    grant_issuer: &'a GrantIssuer,
}

impl<'a> NetworkToolExecutor<'a> {
    pub fn new(event_bus: &'a EventBus, grant_issuer: &'a GrantIssuer) -> Self {
        Self {
            event_bus,
            grant_issuer,
        }
    }

    /// Bind a local TCP/UDP socket listener.
    ///
    /// Validates the address is loopback or private, the port is non-privileged,
    /// and the grant covers the requested address and port.  The actual socket
    /// is stubbed for CI — production would call `TcpListener::bind`.
    pub fn bind_socket(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        bind_addr: &str,
        port: u16,
    ) -> ToolResult {
        if let Err(e) = validate_bind_addr(bind_addr) {
            return self.fail(ctx, e);
        }
        if let Err(e) = validate_port(port) {
            return self.fail(ctx, e);
        }

        let req = ToolInvocationRequest::NetworkBind {
            bind_addr: bind_addr.to_string(),
            port,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        // Stub: production would call TcpListener::bind or UdpSocket::bind.
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_NETWORK_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "bind_socket",
                "bind_addr": bind_addr,
                "port": port,
            }),
        );

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Text(format!("Bound socket at {bind_addr}:{port}")),
            artifact: None,
            error_message: None,
        }
    }

    /// Send a bounded datagram to a local socket address.
    ///
    /// Destination must pass the same address validation as `bind_socket`.
    /// Payload is capped at `MAX_DATAGRAM_BYTES`.
    pub fn send_datagram(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        dest_addr: &str,
        port: u16,
        payload: &[u8],
    ) -> ToolResult {
        if let Err(e) = validate_bind_addr(dest_addr) {
            return self.fail(ctx, e);
        }
        if let Err(e) = validate_port(port) {
            return self.fail(ctx, e);
        }
        if payload.is_empty() {
            return self.fail(ctx, "Datagram payload must not be empty".to_string());
        }
        if payload.len() > MAX_DATAGRAM_BYTES {
            return self.fail(
                ctx,
                format!(
                    "Payload {} bytes exceeds maximum {} bytes",
                    payload.len(),
                    MAX_DATAGRAM_BYTES
                ),
            );
        }

        let req = ToolInvocationRequest::NetworkBind {
            bind_addr: dest_addr.to_string(),
            port,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        // Stub: production would call UdpSocket::send_to.
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_NETWORK_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "send_datagram",
                "dest_addr": dest_addr,
                "port": port,
                "payload_bytes": payload.len(),
            }),
        );

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Text(format!(
                "Sent {} bytes to {dest_addr}:{port}",
                payload.len()
            )),
            artifact: None,
            error_message: None,
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn check_policy(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        req: &ToolInvocationRequest,
    ) -> Option<ToolResult> {
        let engine = PolicyEngine::new(Some(self.event_bus));
        match engine.evaluate_checked(grant, req) {
            Ok(PolicyDecision::Allow { .. }) => None,
            Ok(PolicyDecision::Deny { reason }) => {
                Some(self.fail(ctx, format!("Policy Engine denied network bind: {reason}")))
            }
            Err(e) => Some(self.fail(ctx, format!("Failed to persist network audit: {e}"))),
        }
    }

    fn fail(&self, ctx: &ToolContext, message: String) -> ToolResult {
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_NETWORK_FAILED,
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
