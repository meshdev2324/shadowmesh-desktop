use shadowmesh_core::{
    normalize_activation_code, AntiTamperChecker, AntiTamperConfig, RealityConfig,
};
use std::collections::HashMap;

#[test]
fn test_reality_config_failure_paths() {
    // 1. Wrong prefix
    assert!(RealityConfig::from_vless_uri("vless:/invalid").is_none());

    // 2. Missing @
    assert!(RealityConfig::from_vless_uri("vless://uuid-no-at.com:443?type=tcp").is_none());

    // 3. Missing ?
    assert!(RealityConfig::from_vless_uri("vless://uuid@1.1.1.1:443").is_none());

    // 4. Missing : in host/port
    assert!(RealityConfig::from_vless_uri(
        "vless://uuid@1.1.1.1?type=tcp&security=reality&pbk=p&sid=s"
    )
    .is_none());

    // 5. Invalid port
    assert!(RealityConfig::from_vless_uri(
        "vless://uuid@1.1.1.1:abc?type=tcp&security=reality&pbk=p&sid=s"
    )
    .is_none());

    // 6. Missing pbk/sid
    assert!(RealityConfig::from_vless_uri("vless://uuid@1.1.1.1:443?type=tcp&security=reality")
        .is_none());
    assert!(RealityConfig::from_vless_uri(
        "vless://uuid@1.1.1.1:443?type=tcp&security=reality&pbk=p"
    )
    .is_none());
    assert!(RealityConfig::from_vless_uri(
        "vless://uuid@1.1.1.1:443?type=tcp&security=reality&sid=s"
    )
    .is_none());
}

#[test]
fn test_anti_tamper_signature_verification() {
    let mut expected_hashes = HashMap::new();
    expected_hashes.insert("com.example.app".to_string(), "correct-sig-hash".to_string());
    let checker = AntiTamperChecker::new(AntiTamperConfig { expected_hashes });

    // Success
    assert!(checker
        .verify_app_signature("com.example.app".into(), "correct-sig-hash".into())
        .unwrap());

    // Failure
    assert!(!checker
        .verify_app_signature("com.example.app".into(), "wrong-sig-hash".into())
        .unwrap());

    // Unknown (Skip)
    assert!(checker.verify_app_signature("unknown.app".into(), "any".into()).unwrap());
}

#[test]
fn test_anti_tamper_constant_time_length_mismatch() {
    let mut expected_hashes = HashMap::new();
    expected_hashes.insert("comp".to_string(), "1234".to_string());
    let checker = AntiTamperChecker::new(AntiTamperConfig { expected_hashes });

    // Should return false due to length mismatch in constant_time_compare
    assert!(!checker.verify_component("comp".into(), b"data".to_vec()).unwrap());
}

#[test]
fn test_normalize_activation_code_empty() {
    assert!(normalize_activation_code("".into()).is_none());
    assert!(normalize_activation_code("---".into()).is_none());
    assert_eq!(normalize_activation_code("abc-def".into()), Some("ABCDEF".into()));
}

#[test]
fn test_vpn_manager_runtime_race() {
    // Attempting to trigger the OnceLock race in get_runtime
    let mut handles = vec![];
    for _ in 0..10 {
        handles.push(std::thread::spawn(|| {
            let settings = shadowmesh_core::get_default_user_settings();
            let _ = shadowmesh_core::create_vpn_manager(settings);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_vpn_manager_early_returns_and_empty_states() {
    let settings = shadowmesh_core::get_default_user_settings();
    let manager = shadowmesh_core::VPNManager::new(settings);

    // 1. refresh_node_latencies with no nodes
    manager.refresh_node_latencies(); // Should return early

    // 2. get_best_node with no nodes
    assert!(manager.get_best_node().is_none());

    // 3. get_best_node with all nodes offline
    manager.set_nodes(shadowmesh_core::get_mock_nodes());
    // mock nodes are online by default, let's make them offline
    let mut nodes = shadowmesh_core::get_mock_nodes();
    for n in nodes.iter_mut() {
        n.is_online = false;
    }
    manager.set_nodes(nodes);
    assert!(manager.get_best_node().is_none());
}

#[test]
fn test_reality_config_json_serialization() {
    let config = RealityConfig::new(
        "1.2.3.4".into(),
        443,
        "uuid".into(),
        "pub".into(),
        "sid".into(),
        "sni".into(),
        Some("fp".into()),
    );
    let json = config.to_outbound_config();
    assert!(json.contains("\"publicKey\":\"pub\""));
    assert!(json.contains("\"shortId\":\"sid\""));
}

#[test]
fn test_vpn_manager_activation_plan_variations() {
    let settings = shadowmesh_core::get_default_user_settings();
    let manager = shadowmesh_core::VPNManager::new(settings);

    let plans = vec!["team", "premium", "family", "trial", "unknown"];
    for p in plans {
        manager.activate("code".into(), None, Some(p.into()), 1, 1).unwrap();
        // Just verify it doesn't panic and state is updated
        assert!(manager.is_activated());
    }
}
