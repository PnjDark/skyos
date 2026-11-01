use kernel::artifacts::registry::ArtifactRegistry;
use kernel::events::EventBus;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::Capability;
use tempfile::{tempdir, TempDir};
use tools::hardware::{validate_device_node, HardwareToolExecutor};
use tools::network::{validate_bind_addr, validate_port, NetworkToolExecutor};
use tools::registry::{InvocationRequest, UnifiedToolRegistry};
use tools::types::{ToolContext, ToolStatus};
use uuid::Uuid;

// ── harness ───────────────────────────────────────────────────────────────────

fn runtime() -> (TempDir, EventBus, ArtifactRegistry, GrantIssuer) {
    let temp = tempdir().unwrap();
    let db = temp.path().join("runtime.db");
    let event_bus = EventBus::open(&db).unwrap();
    let registry = ArtifactRegistry::open(&db, temp.path().join("cas")).unwrap();
    (temp, event_bus, registry, GrantIssuer::new())
}

fn hw_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    device_node: &str,
    read_only: bool,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::HardwareAccess {
            device_node: device_node.to_string(),
            read_only,
        }],
        None,
    )
}

fn net_grant(
    issuer: &GrantIssuer,
    task_id: Uuid,
    bind_addr: &str,
    max_port: u16,
) -> kernel::permissions::types::CapabilityGrant {
    issuer.issue_grant(
        "test_agent",
        task_id,
        vec![Capability::NetworkBind {
            bind_addr: bind_addr.to_string(),
            max_port,
        }],
        None,
    )
}

// ── validate_device_node ──────────────────────────────────────────────────────

#[test]
fn device_node_rejects_empty_string() {
    assert!(validate_device_node("").is_err());
}

#[test]
fn device_node_rejects_traversal_sequence() {
    assert!(validate_device_node("/dev/video0/../sda").is_err());
}

#[test]
fn device_node_rejects_null_byte() {
    assert!(validate_device_node("/dev/video0\0").is_err());
}

#[test]
fn device_node_rejects_block_device() {
    assert!(validate_device_node("/dev/sda1").is_err());
    assert!(validate_device_node("/dev/nvme0n1").is_err());
    assert!(validate_device_node("/dev/mem").is_err());
}

#[test]
fn device_node_accepts_camera_and_serial() {
    assert!(validate_device_node("/dev/video0").is_ok());
    assert!(validate_device_node("/dev/ttyUSB0").is_ok());
    assert!(validate_device_node("COM3").is_ok());
}

// ── validate_bind_addr ────────────────────────────────────────────────────────

#[test]
fn bind_addr_accepts_loopback() {
    assert!(validate_bind_addr("127.0.0.1").is_ok());
}

#[test]
fn bind_addr_accepts_private_subnets() {
    assert!(validate_bind_addr("10.0.0.1").is_ok());
    assert!(validate_bind_addr("172.16.0.1").is_ok());
    assert!(validate_bind_addr("192.168.1.100").is_ok());
}

#[test]
fn bind_addr_rejects_public_ip() {
    assert!(validate_bind_addr("8.8.8.8").is_err());
    assert!(validate_bind_addr("1.1.1.1").is_err());
}

#[test]
fn bind_addr_rejects_invalid_string() {
    assert!(validate_bind_addr("not-an-ip").is_err());
    assert!(validate_bind_addr("").is_err());
}

// ── validate_port ─────────────────────────────────────────────────────────────

#[test]
fn port_rejects_privileged_ports() {
    assert!(validate_port(0).is_err());
    assert!(validate_port(80).is_err());
    assert!(validate_port(443).is_err());
    assert!(validate_port(1023).is_err());
}

#[test]
fn port_accepts_ephemeral_range() {
    assert!(validate_port(1024).is_ok());
    assert!(validate_port(8080).is_ok());
    assert!(validate_port(65535).is_ok());
}

// ── HardwareToolExecutor ──────────────────────────────────────────────────────

#[test]
fn hardware_capture_frame_denied_without_grant() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    // Grant for a different device
    let grant = hw_grant(&issuer, task_id, "/dev/video1", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.capture_frame(&ctx, &grant, "/dev/video0", None);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("denied"));
}

#[test]
fn hardware_capture_frame_denied_for_blocked_device() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/sda", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.capture_frame(&ctx, &grant, "/dev/sda", None);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result
        .error_message
        .unwrap()
        .contains("blocked system device"));
}

#[test]
fn hardware_capture_frame_succeeds_with_valid_grant() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/video0", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.capture_frame(&ctx, &grant, "/dev/video0", None);

    assert_eq!(result.status, ToolStatus::Succeeded);
    assert!(result.artifact.is_some());

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|e| e.event_type == "HardwareOperationCompleted"));
}

#[test]
fn hardware_serial_write_denied_with_read_only_grant() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    // read_only=true cannot satisfy a write request
    let grant = hw_grant(&issuer, task_id, "/dev/ttyUSB0", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.serial_write(&ctx, &grant, "/dev/ttyUSB0", 115200, b"ON");

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("denied"));
}

#[test]
fn hardware_serial_write_rejects_invalid_baud_rate() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/ttyUSB0", false);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.serial_write(&ctx, &grant, "/dev/ttyUSB0", 12345, b"ON");

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Baud rate"));
}

#[test]
fn hardware_serial_write_succeeds_with_write_grant() {
    let (_temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/ttyUSB0", false);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut hw = HardwareToolExecutor::new(&event_bus, &mut registry, &issuer);

    let result = hw.serial_write(&ctx, &grant, "/dev/ttyUSB0", 115200, b"ON");

    assert_eq!(result.status, ToolStatus::Succeeded);
}

// ── NetworkToolExecutor ───────────────────────────────────────────────────────

#[test]
fn network_bind_socket_denied_without_matching_grant() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    // Grant covers port up to 8000; request is for 9000
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 8000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let result = net.bind_socket(&ctx, &grant, "127.0.0.1", 9000);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("denied"));
}

#[test]
fn network_bind_socket_rejects_public_address() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "8.8.8.8", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let result = net.bind_socket(&ctx, &grant, "8.8.8.8", 9000);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("not loopback"));
}

#[test]
fn network_bind_socket_rejects_privileged_port() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 65535);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let result = net.bind_socket(&ctx, &grant, "127.0.0.1", 80);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("privileged port"));
}

#[test]
fn network_bind_socket_succeeds_with_valid_grant() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let result = net.bind_socket(&ctx, &grant, "127.0.0.1", 9000);

    assert_eq!(result.status, ToolStatus::Succeeded);

    let events = event_bus.get_events_for_task(&task_id.to_string()).unwrap();
    assert!(events
        .iter()
        .any(|e| e.event_type == "NetworkOperationCompleted"));
}

#[test]
fn network_send_datagram_rejects_oversized_payload() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let oversized = vec![0u8; 65 * 1024];
    let result = net.send_datagram(&ctx, &grant, "127.0.0.1", 9000, &oversized);

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("exceeds maximum"));
}

#[test]
fn network_send_datagram_succeeds_with_valid_grant() {
    let (_temp, event_bus, _, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let net = NetworkToolExecutor::new(&event_bus, &issuer);

    let result = net.send_datagram(&ctx, &grant, "127.0.0.1", 9000, b"hello");

    assert_eq!(result.status, ToolStatus::Succeeded);
}

// ── dispatcher integration ────────────────────────────────────────────────────

#[tokio::test]
async fn dispatcher_rejects_unknown_hardware_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/video0", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            InvocationRequest {
                tool_id: "hardware".into(),
                operation_id: "format_disk".into(),
                parameters: serde_json::json!({}),
                idempotency_key: None,
            },
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

#[tokio::test]
async fn dispatcher_rejects_unknown_network_operation() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            InvocationRequest {
                tool_id: "network".into(),
                operation_id: "port_scan".into(),
                parameters: serde_json::json!({}),
                idempotency_key: None,
            },
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Failed);
    assert!(result.error_message.unwrap().contains("Unknown operation"));
}

#[tokio::test]
async fn dispatcher_routes_hardware_capture_frame() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = hw_grant(&issuer, task_id, "/dev/video0", true);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            InvocationRequest {
                tool_id: "hardware".into(),
                operation_id: "capture_frame".into(),
                parameters: serde_json::json!({ "device_node": "/dev/video0" }),
                idempotency_key: None,
            },
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Succeeded);
    assert!(result.artifact.is_some());
}

#[tokio::test]
async fn dispatcher_routes_network_bind_socket() {
    let (temp, event_bus, mut registry, issuer) = runtime();
    let task_id = Uuid::new_v4();
    let grant = net_grant(&issuer, task_id, "127.0.0.1", 9000);
    let ctx = ToolContext::new(task_id, "test_agent");
    let mut dispatcher = UnifiedToolRegistry::new(&event_bus, &mut registry, &issuer);

    let result = dispatcher
        .dispatch(
            &ctx,
            &grant,
            InvocationRequest {
                tool_id: "network".into(),
                operation_id: "bind_socket".into(),
                parameters: serde_json::json!({ "bind_addr": "127.0.0.1", "port": 9000 }),
                idempotency_key: None,
            },
            temp.path(),
        )
        .await;

    assert_eq!(result.status, ToolStatus::Succeeded);
}

// ── schema export covers new tool families ────────────────────────────────────

#[test]
fn schema_export_covers_hardware_and_network() {
    let schemas = UnifiedToolRegistry::export_schemas();
    let tool_ids: Vec<&str> = schemas.iter().map(|s| s.tool_id.as_str()).collect();
    assert!(tool_ids.contains(&"hardware"));
    assert!(tool_ids.contains(&"network"));
}

#[test]
fn hardware_and_network_schemas_contain_no_grant_fields() {
    let schemas = UnifiedToolRegistry::export_schemas();
    let hw_net: Vec<_> = schemas
        .iter()
        .filter(|s| s.tool_id == "hardware" || s.tool_id == "network")
        .collect();
    assert!(!hw_net.is_empty());
    for s in hw_net {
        let serialized = serde_json::to_string(s).unwrap();
        assert!(!serialized.contains("grant_id"));
        assert!(!serialized.contains("revoked"));
    }
}
