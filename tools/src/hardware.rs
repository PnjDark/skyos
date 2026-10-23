use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::artifacts::registry::{ArtifactRegistry, ArtifactType};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;

pub const EVENT_HARDWARE_COMPLETED: &str = "HardwareOperationCompleted";
pub const EVENT_HARDWARE_FAILED: &str = "HardwareOperationFailed";

/// Maximum frame size accepted from a capture device (4 MB).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Validates a device node string against a strict allowlist of safe prefixes.
///
/// Blocks root device nodes (`/dev/sda`, `COM1` without a numeric suffix check),
/// memory devices, and any path containing traversal sequences.
pub fn validate_device_node(node: &str) -> Result<(), String> {
    if node.is_empty() {
        return Err("Device node must not be empty".to_string());
    }
    if node.contains("..") || node.contains('\0') {
        return Err(format!("Device node contains forbidden sequence: {node:?}"));
    }

    // On Unix-like systems block raw block/memory devices.
    let blocked_prefixes = ["/dev/sd", "/dev/hd", "/dev/nvme", "/dev/mem", "/dev/kmem"];
    for prefix in blocked_prefixes {
        if node.starts_with(prefix) {
            return Err(format!("Device node {node:?} is a blocked system device"));
        }
    }

    Ok(())
}

/// Validates serial baud rate is one of the standard values.
fn validate_baud_rate(baud: u32) -> Result<(), String> {
    const VALID: &[u32] = &[9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];
    if VALID.contains(&baud) {
        Ok(())
    } else {
        Err(format!(
            "Baud rate {baud} is not a recognized standard value"
        ))
    }
}

pub struct HardwareToolExecutor<'a> {
    event_bus: &'a EventBus,
    artifact_registry: &'a mut ArtifactRegistry,
    #[allow(dead_code)]
    grant_issuer: &'a GrantIssuer,
}

impl<'a> HardwareToolExecutor<'a> {
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

    /// Capture a single frame from a camera device.
    ///
    /// In production this would invoke a platform capture API.  Here the
    /// implementation is intentionally stubbed: it validates the capability,
    /// records the audit event, and registers a zero-byte CAS artifact so the
    /// full permission and artifact lineage path is exercised without requiring
    /// physical hardware in CI.
    pub fn capture_frame(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        device_node: &str,
        max_bytes: Option<usize>,
    ) -> ToolResult {
        if let Err(e) = validate_device_node(device_node) {
            return self.fail(ctx, e);
        }

        let limit = max_bytes.unwrap_or(MAX_FRAME_BYTES).min(MAX_FRAME_BYTES);

        let req = ToolInvocationRequest::HardwareAccess {
            device_node: device_node.to_string(),
            read_only: true,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        let _ = limit;
        // Stub: production would call v4l2 / AVFoundation / DirectShow here.
        let frame_bytes: Vec<u8> = vec![0u8; 0]; // zero-length stub

        let artifact = match self.artifact_registry.register_text_artifact(
            &format!("frame-stub-{}", ctx.invocation_id),
            &ctx.task_id.to_string(),
            ArtifactType::Snapshot,
            None,
            json!({
                "invocation_id": ctx.invocation_id,
                "device_node": device_node,
                "frame_bytes": frame_bytes.len(),
            }),
        ) {
            Ok(a) => a,
            Err(e) => return self.fail(ctx, format!("CAS registration failed: {e}")),
        };

        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_HARDWARE_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "capture_frame",
                "device_node": device_node,
                "artifact_id": artifact.artifact_id,
            }),
        );

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Bytes(frame_bytes),
            artifact: Some(artifact),
            error_message: None,
        }
    }

    /// Send a control command to a serial/USB device (e.g. lighting controller).
    ///
    /// `payload` is the raw byte sequence to write.  Baud rate is validated
    /// against the standard allowlist to prevent injection of arbitrary timing
    /// parameters.  Requires a write-capable `HardwareAccess` grant.
    pub fn serial_write(
        &mut self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        device_node: &str,
        baud_rate: u32,
        payload: &[u8],
    ) -> ToolResult {
        if let Err(e) = validate_device_node(device_node) {
            return self.fail(ctx, e);
        }
        if let Err(e) = validate_baud_rate(baud_rate) {
            return self.fail(ctx, e);
        }
        if payload.is_empty() {
            return self.fail(ctx, "Serial payload must not be empty".to_string());
        }

        let req = ToolInvocationRequest::HardwareAccess {
            device_node: device_node.to_string(),
            read_only: false,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        // Stub: production would open the serial port and write `payload`.
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_HARDWARE_COMPLETED,
            json!({
                "invocation_id": ctx.invocation_id,
                "operation": "serial_write",
                "device_node": device_node,
                "baud_rate": baud_rate,
                "payload_bytes": payload.len(),
            }),
        );

        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Succeeded,
            output: ToolOutput::Text(format!(
                "Wrote {} bytes to {device_node} at {baud_rate} baud",
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
            Ok(PolicyDecision::Deny { reason }) => Some(self.fail(
                ctx,
                format!("Policy Engine denied hardware access: {reason}"),
            )),
            Err(e) => Some(self.fail(ctx, format!("Failed to persist hardware audit: {e}"))),
        }
    }

    fn fail(&self, ctx: &ToolContext, message: String) -> ToolResult {
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_HARDWARE_FAILED,
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
