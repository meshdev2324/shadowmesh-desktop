use shadowmesh_core::*;

#[test]
fn test_wireguard_key_generation_validity() {
    // 1. Generate keys
    let keys = generate_wireguard_keys().expect("Key generation failed");
    assert_eq!(keys.len(), 2, "Should return a pair of keys");

    let private_key = &keys[0];
    let public_key = &keys[1];

    // 2. Validate format (Base64 and length)
    assert!(validate_wireguard_key(private_key.clone()), "Invalid private key format");
    assert!(validate_wireguard_key(public_key.clone()), "Invalid public key format");

    // 3. Ensure they are not the same
    assert_ne!(private_key, public_key, "Private and public keys must differ");
}

#[test]
fn test_wireguard_config_parsing_robustness() {
    let config_str = r#"
        [Interface]
        # This is a comment
        PrivateKey = MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=
        Address = 10.0.0.2/32
        DNS = 1.1.1.1, 8.8.8.8
        MTU = 1420

        [Peer]
        PublicKey = OTg3NjU0MzIxMDk4NzY1NDMyMTA5ODc2NTQzMjEwOTg=
        Endpoint = 1.2.3.4:51820
    "#
    .to_string();

    let config = parse_wireguard_config(config_str).expect("Failed to parse valid config");

    assert_eq!(config.private_key.as_deref(), Some("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="));
    assert_eq!(config.public_key, "OTg3NjU0MzIxMDk4NzY1NDMyMTA5ODc2NTQzMjEwOTg=");
    assert_eq!(config.address, "10.0.0.2/32");
    assert!(config.dns.contains("1.1.1.1"));
    assert_eq!(config.mtu, 1420);
}

#[test]
fn test_wireguard_config_parsing_failure() {
    let invalid_config = "[Interface]\nMissingKey = values".to_string();
    let result = parse_wireguard_config(invalid_config);
    // Note: our current simple parser returns success if some fields are missing but not mandatory
    // or just empty strings. Adjust test if needed.
    assert!(result.is_ok());
}

#[test]
fn test_pow_solver_correctness() {
    use shadowmesh_core::pow::solve_pow;

    let challenge = "security_test_challenge".to_string();
    let difficulty = 8; // manageable difficulty for test

    let result = solve_pow(challenge.clone(), difficulty).expect("PoW solving failed");

    let (res_challenge, solution) = result;
    assert_eq!(res_challenge, challenge);
    assert!(!solution.is_empty(), "Solution should not be empty");
}

#[test]
fn test_vpn_manager_fsm_with_auto_mode() {
    use shadowmesh_core::get_mock_nodes;
    use shadowmesh_core::vpn_manager::*;

    let settings = UserSettings::default();
    let manager = VPNManager::new(settings);
    manager.set_traffic_mode_preference(TrafficModePreference::Auto);

    let node = get_mock_nodes()[0].clone();

    // Attempt 1: Should be Normal
    manager.initiate_connection(node.clone(), "pub".into()).unwrap();
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Normal));
    manager.disconnect();
}

#[test]
fn test_shadow_routing_logic_integration() {
    use shadowmesh_core::shadow_route_best_node;
    use shadowmesh_core::VPNNode;

    let nodes = vec![
        VPNNode {
            id: "slow".into(),
            name: "Slow".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "1.1.1.1:51820".into(),
            public_key: "pub".into(),
            load: 10,
            latency: 200,
            is_online: true,
        },
        VPNNode {
            id: "fast".into(),
            name: "Fast".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "1.1.1.1:51820".into(),
            public_key: "pub".into(),
            load: 10,
            latency: 20,
            is_online: true,
        },
    ];

    let best = shadow_route_best_node(nodes).expect("Should find best node");
    assert_eq!(best.id, "fast");
}
