use shadowmesh_core::{ConnectionStatus, UserSettings, VPNManager, VPNNode};

#[test]
fn test_core_direct_connection_flow() {
    let settings = UserSettings::default();
    let manager = VPNManager::new(settings);

    // 1. Initial State
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);

    // 2. Mock Activation
    manager
        .activate(
            "TEST-CODE".to_string(),
            Some("TEST-TOKEN".to_string()),
            Some("Solo".to_string()),
            1,
            30,
        )
        .unwrap();
    assert!(manager.is_activated());

    // 3. Setup Mock Node
    let node = VPNNode {
        id: "node-1".into(),
        name: "Test Node".into(),
        region: "US-West".into(),
        country: "US".into(),
        endpoint: "1.2.3.4:51820".into(),
        public_key: "abc/123=".into(),
        load: 10,
        latency: 50,
        is_online: true,
    };

    // 4. Initiate Connection (Direct)
    manager.initiate_connection(node.clone(), "pub-key".into()).unwrap();

    // Core should transition to ConnectingDirect
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingDirect);

    // 5. Complete Connection
    // In a real app, the platform layer (Java/Swift/Rust Daemon) would
    // spawn the tunnel and then call complete_connection.
    manager.complete_connection();
    assert_eq!(manager.get_status(), ConnectionStatus::Connected);

    // 6. Disconnect
    manager.disconnect();
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);
}

#[test]
fn test_wireguard_key_generation() {
    let keys = shadowmesh_core::generate_wireguard_keys().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(shadowmesh_core::validate_wireguard_key(keys[1].clone()));
}
