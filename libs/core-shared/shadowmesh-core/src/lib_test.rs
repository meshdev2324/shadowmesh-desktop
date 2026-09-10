use super::*;

#[test]
fn test_parse_wireguard_config_with_traffic_mode_metadata() {
    // Note: parse_wireguard_config expects valid keys or it returns Other.
    // For a unit test, we use valid base64 placeholders.
    let valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let config_str = format!(
        r#"
# TrafficMode: fragmented
[Interface]
PrivateKey = {}
Address = 10.200.0.2/24
MTU = 576

[Peer]
PublicKey = {}
Endpoint = 1.2.3.4:51820
"#,
        valid_key, valid_key
    );

    let config = parse_wireguard_config(config_str).unwrap();
    assert_eq!(config.traffic_mode, "fragmented");
    assert_eq!(config.mtu, 576);
}

#[test]
fn test_is_fragmentation_recommended_logic() {
    let engine = crate::shadow_router::preferred_mode_for_region;

    // High-risk countries
    assert_eq!(engine("CN"), TrafficMode::Fragmented);
    assert_eq!(engine("IR"), TrafficMode::Fragmented);
    assert_eq!(engine("RU"), TrafficMode::Fragmented);
    assert_eq!(engine("SA"), TrafficMode::Fragmented);

    // Safe countries
    assert_eq!(engine("US"), TrafficMode::Normal);
    assert_eq!(engine("DE"), TrafficMode::Normal);
    assert_eq!(engine("GB"), TrafficMode::Normal);
}

#[test]
fn test_normalize_activation_code() {
    let valid = "ABCDE12345FGHIJ67890KLMNO";
    assert_eq!(normalize_activation_code(valid.to_string()), Some(valid.to_string()));

    assert_eq!(
        normalize_activation_code("uvpn-abcde-12345-fghij-67890-klmno".to_string()),
        Some(valid.to_string())
    );
    assert_eq!(
        normalize_activation_code("  ABCDE 12345 FGHIJ 67890 KLMNO  ".to_string()),
        Some(valid.to_string())
    );

    // Invalid
    assert_eq!(normalize_activation_code("TOO-SHORT".to_string()), None);
    assert_eq!(
        normalize_activation_code("THIS-ONE-IS-TOO-LONG-DEFINITELY-TOO-LONG".to_string()),
        None
    );
    assert_eq!(normalize_activation_code("!!!!-12345-fghij-67890-klmno".to_string()), None);
}

#[test]
fn test_mock_nodes_integrity() {
    let nodes = get_mock_nodes();
    assert!(!nodes.is_empty());
    assert_eq!(nodes[0].country, "United States");
}

#[test]
fn test_quantum_tunneling_constants() {
    assert_eq!(get_quantum_mtu(), 576);
    assert_eq!(get_quantum_tcp_mss(), 536);
}

#[test]
fn test_pii_scrubbing() {
    let raw = "Connect to 1.2.3.4 using key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= and code ABCDE12345ABCDE12345ABCDE";
    let scrubbed = scrub_pii(raw);

    assert!(scrubbed.contains("[REDACTED_IP]"));
    assert!(scrubbed.contains("[REDACTED_KEY]"));
    assert!(scrubbed.contains("[REDACTED_CODE]"));
    assert!(!scrubbed.contains("1.2.3.4"));
}

#[test]
fn test_vpn_manager_connection_flow() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);

    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);

    // Activation
    manager.activate("code".into(), Some("token".into()), None, 3, 30).unwrap();
    assert!(manager.is_activated());
    assert_eq!(manager.get_devices_remaining(), 3);
    assert_eq!(manager.get_remaining_days(), 30);

    let node = get_mock_nodes().first().unwrap().clone();
    manager.initiate_connection(node, "test-pubkey".to_string()).unwrap();

    // Default mock behavior should lead to ConnectingDirect (Normal mode for US)
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingDirect);

    manager.complete_connection();
    assert_eq!(manager.get_status(), ConnectionStatus::Connected);

    manager.disconnect();
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);
}

#[test]
fn test_vpn_manager_high_risk_auto_mode() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);
    manager.activate("code".into(), None, None, 1, 1).unwrap();

    let mut node = get_mock_nodes().first().unwrap().clone();
    node.country = "China".to_string();
    node.region = "CN".to_string();

    manager.initiate_connection(node, "test-pubkey".to_string()).unwrap();

    // CN should trigger Fragmentation
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingFragmented);
}
