use serde_json::json;
use shadowmesh_core::*;

#[test]
fn test_shadow_mesh_error_variants() {
    let err = ShadowMeshError::Unauthorized("Invalid token".to_string());
    assert!(err.to_string().contains("Authentication failed"));

    let err = ShadowMeshError::TooManyRequests("Rate limit".to_string());
    assert!(err.to_string().contains("Server overloaded"));

    let err = ShadowMeshError::ServerError("Internal error".to_string());
    assert!(err.to_string().contains("Internal server error"));
}

#[test]
fn test_heartbeat_response_deserialization() {
    let json = json!({
        "message": "Alive (Buffered)",
        "device_id": "dev123",
        "session_active": true,
        "subscription_notice": "Your plan expires in 3 days",
        "next_heartbeat": "60s"
    });

    let resp: HeartbeatResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.device_id, "dev123");
    assert!(resp.session_active);
    assert_eq!(resp.subscription_notice, "Your plan expires in 3 days");
}

#[test]
fn test_identity_info_deserialization() {
    let json = json!({
        "id": 1,
        "public_key": "pubkey",
        "is_admin": true,
        "mfa_enabled": false,
        "created_at": "2024-01-01T12:00:00Z"
    });

    let info: IdentityInfo = serde_json::from_value(json).unwrap();
    assert_eq!(info.id, 1);
    assert!(info.is_admin);
    assert!(!info.mfa_enabled);
}

#[test]
fn test_health_status_deserialization() {
    let json = json!({
        "status": "online",
        "version": "1.0.0",
        "uptime_seconds": 3600
    });

    let status: HealthStatus = serde_json::from_value(json).unwrap();
    assert_eq!(status.status, "online");
    assert_eq!(status.uptime_seconds, 3600);
}

#[test]
fn test_dpi_detection_sync_logic() {
    // Test that VPNManager correctly updates its mode based on DPI detection
    let settings = UserSettings {
        kill_switch_enabled: true,
        dns_leak_protection: true,
        emergency_recovery_enabled: false,
        dns_servers: vec!["1.1.1.1".to_string()],
    };

    let manager = VPNManager::new(settings);
    manager.set_traffic_mode_preference(TrafficModePreference::Auto);

    // Simulate DPI detection
    manager.set_dpi_detected(true);
    assert!(manager.is_dpi_detected());

    // Check mode determination (should skip Normal)
    let node = VPNNode {
        id: "test".to_string(),
        name: "Test Node".to_string(),
        region: "US".to_string(),
        country: "US".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        public_key: "pub".to_string(),
        load: 10,
        latency: 50,
        is_online: true,
    };

    // First attempt with DPI detected should use Fragmented
    let _ = manager.initiate_connection(node.clone(), "device_pk".to_string());
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Fragmented));

    // Further attempts should escalate to Reality if fragmented fails (simulated by incrementing attempt)
    // In a real scenario, initiate_connection is called repeatedly.
    // For test simplicity, let's just verify the logic in initiate_connection.
}
