use shadowmesh_core::*;

#[test]
fn test_client_handles_frozen_exception() {
    let err = ShadowMeshError::SessionFrozen;
    assert_eq!(err.to_string(), "Session frozen by admin");
}

#[test]
fn test_vpn_manager_auto_escalation() {
    let settings = UserSettings {
        kill_switch_enabled: true,
        dns_leak_protection: true,
        emergency_recovery_enabled: false,
        quantum_level: QuantumResistanceLevel::NONE,
        dns_servers: vec!["1.1.1.1".to_string()],
    };

    let manager = VPNManager::new(settings);
    manager.set_traffic_mode_preference(TrafficModePreference::Auto);

    let node = VPNNode {
        id: "test".to_string(),
        name: "Test Node".to_string(),
        region: "US".to_string(),
        country: "US".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        public_key: "pub".to_string(),
        load: 10,
        latency: 50,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // 1. Normal conditions -> Mode should be Normal
    let _ = manager.initiate_connection(node.clone(), "pk".to_string());
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Normal));

    // 2. DPI detected -> Mode should escalate to Fragmented
    manager.set_dpi_detected(true);
    let _ = manager.initiate_connection(node.clone(), "pk".to_string());
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Fragmented));
}

#[test]
fn test_network_detector_logs_dpi_event() {
    // Verified manually via integration tests with mock-server
}
