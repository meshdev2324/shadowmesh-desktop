use shadowmesh_core::*;

#[test]
fn test_reality_handshake_simulation() {
    // Reality protocol depends on DH exchange
    let alice_priv = generate_dh_private_key();
    let alice_pub = compute_dh_public_key(alice_priv.clone());

    let bob_priv = generate_dh_private_key();
    let bob_pub = compute_dh_public_key(bob_priv.clone());

    let alice_shared = compute_dh_shared_secret(alice_priv, bob_pub);
    let bob_shared = compute_dh_shared_secret(bob_priv, alice_pub);

    assert_eq!(alice_shared, bob_shared, "Shared secrets must match");

    let token = derive_session_token(alice_shared);
    assert_eq!(token.len(), 64, "Session token should be a hex-encoded SHA256 (64 chars)");
}

#[test]
fn test_fragmentation_packet_math() {
    let mtu = get_quantum_mtu();
    let mss = get_quantum_tcp_mss();

    assert!(mtu > 0);
    assert!(mss > 0);
    assert!(mss < mtu, "TCP MSS must be less than MTU to account for headers");

    // ShadowMesh uses 576 MTU for Quantum Tunneling per PROTOCOLS.md
    assert_eq!(mtu, 576);
    assert_eq!(mss, 536);
}

#[test]
fn test_shadow_router_weighted_selection() {
    let nodes = vec![
        VPNNode {
            id: "n1".into(),
            name: "High Load".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "1.1.1.1:51820".into(),
            public_key: "pk1".into(),
            load: 95, // 95% load
            latency: 20,
            is_online: true,
        },
        VPNNode {
            id: "n2".into(),
            name: "Low Load".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "1.1.1.2:51820".into(),
            public_key: "pk2".into(),
            load: 10, // 10% load
            latency: 50,
            is_online: true,
        },
    ];

    let best = shadow_route_best_node(nodes).expect("Should find a best node");
    // Even though n1 has lower latency, the high load should make n2 the preferred choice
    // assuming the shadow_router implements load-weighted selection.
    assert_eq!(
        best.id, "n2",
        "Should prefer low load node over slightly faster but overloaded node"
    );
}

#[test]
fn test_preferred_traffic_mode_by_region() {
    // Censored regions should prefer Stealth (Fragmented/Reality)
    let cn_mode = preferred_traffic_mode_for_region("CN".into());
    assert!(
        cn_mode.contains("Stealth")
            || cn_mode.contains("Reality")
            || cn_mode.contains("Fragmented")
    );

    // Free regions should prefer Speed (Normal)
    let us_mode = preferred_traffic_mode_for_region("US".into());
    assert!(us_mode.contains("Speed") || us_mode.contains("Normal"));
}

#[test]
fn test_anti_tamper_logic_scenarios() {
    use std::collections::HashMap;
    let mut hashes = HashMap::new();
    hashes.insert("com.shadowmesh".into(), "SIGNATURE_ALPHA".into());

    let checker = AntiTamperChecker::new(AntiTamperConfig { expected_hashes: hashes });

    // Case 1: Known app, correct hash
    assert!(checker
        .verify_app_signature("com.shadowmesh".into(), "SIGNATURE_ALPHA".into())
        .unwrap());

    // Case 2: Known app, wrong hash
    assert!(!checker
        .verify_app_signature("com.shadowmesh".into(), "SIGNATURE_BETA".into())
        .unwrap());

    // Case 3: Unknown app (bypass for dev/debug variants)
    assert!(checker.verify_app_signature("com.shadowmesh.dev".into(), "ANY".into()).unwrap());
}
