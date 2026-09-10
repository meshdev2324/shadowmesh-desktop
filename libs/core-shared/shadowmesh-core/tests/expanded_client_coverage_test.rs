use shadowmesh_core::*;
use std::collections::HashMap;

#[test]
fn test_kill_switch_manager_full() {
    let ks = KillSwitchManager::new();
    assert!(!ks.is_active());

    // Feature flags
    assert!(ks.is_feature_enabled("any".to_string()));
    ks.set_feature_enabled("feature1".to_string(), false);
    assert!(!ks.is_feature_enabled("feature1".to_string()));

    // Trigger
    ks.trigger_kill_switch("test failure".into());
    assert!(ks.is_active());
    assert!(!ks.is_feature_enabled("feature2".to_string())); // All disabled when KS active

    // Audit log
    let log = ks.get_audit_log();
    assert!(log.iter().any(|e| e.event_type == "kill_switch_triggered"));

    // Cached state
    let state = ks.get_cached_state().unwrap();
    assert!(state.is_active);

    // Deactivate
    ks.deactivate_kill_switch();
    assert!(!ks.is_active());

    // Fallback mode
    ks.set_fallback_mode(true);
    assert!(ks.is_fallback_mode());
}

#[test]
fn test_traffic_analytics_full() {
    let ta = TrafficAnalytics::new();
    assert_eq!(ta.get_total_bytes(), 0);

    let stats = ConnectionStats {
        bytes_received: 1000,
        bytes_sent: 500,
        packets_received: 10,
        packets_sent: 5,
        last_handshake: 0,
        connected_since: 0,
    };

    ta.record_stats("server1".into(), stats.clone());
    assert_eq!(ta.get_total_bytes(), 1500);
    assert_eq!(ta.get_bytes_this_month(), 1500);

    ta.reset_month();
    assert_eq!(ta.get_bytes_this_month(), 0);
    assert_eq!(ta.get_total_bytes(), 1500);
}

#[test]
fn test_vpn_manager_comprehensive_fsm() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);

    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);
    assert!(!manager.is_activated());

    // Activation
    manager.activate("code".into(), Some("token".into()), None, 5, 30).unwrap();
    assert!(manager.is_activated());
    assert_eq!(manager.get_devices_remaining(), 5);
    assert_eq!(manager.get_remaining_days(), 30);

    // Node management
    let node = VPNNode {
        id: "node1".into(),
        name: "Node 1".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "1.2.3.4:51820".into(),
        public_key: "pk".into(),
        load: 10,
        latency: 50,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };
    manager.set_nodes(vec![node.clone()]);
    assert_eq!(manager.get_nodes().len(), 1);

    manager.set_selected_node(node.clone());
    assert_eq!(manager.get_selected_node().unwrap().id, "node1");

    // Connection flow
    manager.initiate_connection(node.clone(), "dev_pk".into()).unwrap();
    assert!(matches!(
        manager.get_status(),
        ConnectionStatus::ConnectingDirect | ConnectionStatus::Connected
    ));

    manager.complete_connection();
    assert_eq!(manager.get_status(), ConnectionStatus::Connected);

    // Stats
    let stats = ConnectionStats {
        bytes_received: 100,
        bytes_sent: 200,
        packets_received: 1,
        packets_sent: 2,
        last_handshake: 12345,
        connected_since: 54321,
    };
    manager.set_stats(stats.clone());
    assert_eq!(manager.get_stats().bytes_received, 100);

    // Pause/Resume
    manager.pause(10).unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::Paused);
    assert!(manager.get_paused_until().is_some());

    manager.resume();
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);

    // Split tunnel
    let mut st = manager.get_split_tunnel_config();
    st.enabled = true;
    st.app_list = vec!["com.pkg".into()];
    manager.set_split_tunnel_config(st);
    assert!(manager.get_split_tunnel_config().enabled);
}

#[test]
fn test_api_client_error_handling() {
    let client = create_api_client("https://invalid-url-that-does-not-exist.test".into()).unwrap();

    // Connection failure expected
    let result = client.get_nodes();
    assert!(matches!(result, Err(ShadowMeshError::ConnectionFailed | ShadowMeshError::Other(_))));

    // Adaptive friction simulation in unit test if possible, but ApiClient is hard to mock without traits.
    // We'll rely on the server integration tests for real 402 flows.
}

#[test]
fn test_api_client_configuration_accessors() {
    let client = create_api_client("http://localhost".into()).unwrap();

    client.set_auth_token(Some("test-token".into()));
    client.set_traffic_mode(Some(TrafficMode::Fragmented));
    client.set_pow_solution("sol".into(), "chal".into());
}

#[test]
fn test_traffic_preferences_defaults() {
    let tp = create_traffic_preferences();
    assert_eq!(tp.mode_preference, TrafficModePreference::Auto);
    assert!(tp.prioritize_wifi);
    assert!(!tp.restrict_background_data);
}

#[test]
fn test_vpn_manager_best_node_logic() {
    let manager = VPNManager::new(get_default_user_settings());
    let nodes = vec![
        VPNNode {
            id: "n1".into(),
            name: "n1".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "e1".into(),
            public_key: "p1".into(),
            load: 50,
            latency: 100,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        },
        VPNNode {
            id: "n2".into(),
            name: "n2".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "e2".into(),
            public_key: "p2".into(),
            load: 10,
            latency: 20,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        },
    ];
    manager.set_nodes(nodes);

    let best = manager.get_best_node().unwrap();
    assert_eq!(best.id, "n2");
}

#[test]
fn test_vpn_manager_status_transitions() {
    let manager = VPNManager::new(get_default_user_settings());
    manager.activate("c".into(), None, None, 1, 1).unwrap();

    let node = VPNNode {
        id: "n".into(),
        name: "n".into(),
        region: "r".into(),
        country: "c".into(),
        endpoint: "e".into(),
        public_key: "p".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // VPNManager's public start path is initiate_connection(); the traffic
    // mode is picked by the state machine. Forcing Reality via set_traffic_mode
    // makes the "current mode != Normal" branch keep Reality.
    manager.set_traffic_mode(TrafficMode::Reality);
    manager.initiate_connection(node.clone(), "device-key".into()).unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingReality);

    manager.complete_connection();
    assert_eq!(manager.get_status(), ConnectionStatus::Connected);

    manager.disconnect();
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);
}

#[test]
fn test_vpn_manager_connection_timeout() {
    let manager = VPNManager::new(get_default_user_settings());
    let node = VPNNode {
        id: "n".into(),
        name: "n".into(),
        region: "r".into(),
        country: "c".into(),
        endpoint: "e".into(),
        public_key: "p".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    manager.set_traffic_mode(TrafficMode::Normal);
    manager.initiate_connection(node, "device-key".into()).unwrap();
    assert!(!manager.is_connection_timed_out());

    // We can't easily fast-forward time in these tests without mocking Instant::now
    // but we've verified the logic reads from the attempt state.
}

#[test]
fn test_vpn_manager_pause_expiry() {
    let manager = VPNManager::new(get_default_user_settings());
    manager.activate("c".into(), None, None, 1, 1).unwrap();

    // Pause for minimum duration
    manager.pause(5).unwrap();
    assert!(!manager.check_pause_expiry()); // Not expired yet
}

#[test]
fn test_vpn_manager_settings_and_stats() {
    let mut settings = get_default_user_settings();
    settings.kill_switch_enabled = true;
    let manager = VPNManager::new(settings);

    assert!(manager.is_kill_switch_enabled());
    manager.set_kill_switch_enabled(false);
    assert!(!manager.is_kill_switch_enabled());

    let stats = manager.get_stats();
    assert_eq!(stats.bytes_received, 0);

    let user_settings = manager.get_user_settings();
    assert!(user_settings.kill_switch_enabled); // initial value from constructor settings
}

#[test]
fn test_vpn_manager_traffic_preference_logic() {
    let manager = VPNManager::new(get_default_user_settings());
    assert_eq!(manager.get_traffic_mode_preference(), TrafficModePreference::Auto);

    manager.set_traffic_mode_preference(TrafficModePreference::Stealth);
    assert_eq!(manager.get_traffic_mode_preference(), TrafficModePreference::Stealth);
}

#[test]
fn test_traffic_analytics_monthly_limit_check() {
    let ta = TrafficAnalytics::new();
    let stats = ConnectionStats {
        bytes_received: 10 * 1024 * 1024, // 10MB
        bytes_sent: 0,
        packets_received: 0,
        packets_sent: 0,
        last_handshake: 0,
        connected_since: 0,
    };
    ta.record_stats("s1".into(), stats);
    assert!(ta.get_bytes_this_month() > 0);
}

#[test]
fn test_network_detector_logic() {
    let client = create_api_client("http://localhost".into()).unwrap();
    let _detector = create_network_detector(client, None);
    // Real detection requires network, but we can verify it doesn't panic on init
}

#[test]
fn test_vpn_manager_mode_preference_speed() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);
    manager.activate("c".into(), None, None, 1, 1).unwrap();
    manager.set_traffic_mode_preference(TrafficModePreference::Speed);

    let node = VPNNode {
        id: "n".into(),
        name: "n".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "e".into(),
        public_key: "p".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // First attempt -> Normal
    manager.initiate_connection(node.clone(), "p".into()).unwrap();
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Normal));
}

#[test]
fn test_vpn_manager_mode_preference_stealth() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);
    manager.activate("c".into(), None, None, 1, 1).unwrap();
    manager.set_traffic_mode_preference(TrafficModePreference::Stealth);

    let node = VPNNode {
        id: "n".into(),
        name: "n".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "e".into(),
        public_key: "p".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // Attempt 1 -> Fragmented
    manager.initiate_connection(node.clone(), "p".into()).unwrap();
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Fragmented));
}

#[test]
fn test_reality_dh_flow() {
    let priv_key = generate_dh_private_key();
    assert!(!priv_key.is_empty());

    let pub_key = compute_dh_public_key(priv_key.clone());
    assert!(!pub_key.is_empty());

    let other_priv = generate_dh_private_key();
    let other_pub = compute_dh_public_key(other_priv.clone());

    let secret1 = compute_dh_shared_secret(priv_key, other_pub.clone());
    let secret2 = compute_dh_shared_secret(other_priv, pub_key);

    assert_eq!(secret1, secret2);

    let token = derive_session_token(secret1);
    assert_eq!(token.len(), 64); // Hex SHA256
}

#[test]
fn test_vpn_manager_auto_retry_modes() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);
    manager.activate("code".into(), None, None, 1, 1).unwrap();
    manager.set_traffic_mode_preference(TrafficModePreference::Auto);

    let node = VPNNode {
        id: "n".into(),
        name: "N".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "1.1.1.1:51820".into(),
        public_key: "pk".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // Attempt 0 -> Normal
    manager.initiate_connection(node.clone(), "p".into()).unwrap();
    assert_eq!(manager.get_current_connection_mode(), Some(TrafficMode::Normal));
}

#[test]
fn test_api_client_heartbeat_api() {
    let client = create_api_client("http://localhost".into()).unwrap();
    // Verify it doesn't crash on call (expected connection failure)
    let _ = client.heartbeat(HeartbeatRequest {
        device_id: "dev".into(),
        background_mode: true,
        deep_fingerprint: None,
        bytes_sent_quantum: None,
        bytes_received_quantum: None,
        bytes_sent_reality: None,
        bytes_received_reality: None,
    });
}

#[test]
fn test_api_client_qr_apis() {
    let client = create_api_client("http://localhost".into()).unwrap();
    let _ = client.qr_generate("d".into(), "n".into(), "o".into(), "v".into(), "a".into());
    let _ = client.qr_status("t".into());
    let _ = client.qr_authorize("t".into());
}

#[test]
fn test_security_logger_scrubbing() {
    let temp = tempfile::tempdir().unwrap();
    let logger =
        SecurityEventLogger::new("dev".into(), "1".into(), temp.path().to_str().unwrap().into())
            .unwrap();

    // Scrub IP
    logger.log_event(SecurityEventType::LoginAttempt, "from 192.168.1.1".into(), true, None);
    assert!(logger.get_events()[0].details.contains("[REDACTED_IP]"));

    // Scrub Key
    logger.log_event(
        SecurityEventType::LoginAttempt,
        "key: MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=".into(),
        true,
        None,
    );
    assert!(logger.get_events()[1].details.contains("[REDACTED_KEY]"));
}

#[test]
fn test_anti_tamper_signature_verification() {
    let mut hashes = HashMap::new();
    hashes.insert("com.pkg".into(), "valid_sig".into());
    let checker = AntiTamperChecker::new(AntiTamperConfig { expected_hashes: hashes });

    assert!(checker.verify_app_signature("com.pkg".into(), "valid_sig".into()).unwrap());
    assert!(!checker.verify_app_signature("com.pkg".into(), "wrong_sig".into()).unwrap());
    assert!(checker.verify_app_signature("unknown".into(), "any".into()).unwrap());
}

#[test]
fn test_vpn_manager_pause_validation() {
    let manager = VPNManager::new(get_default_user_settings());

    // Fail if not activated
    assert!(matches!(manager.pause(10), Err(ShadowMeshError::ConnectionFailed)));

    manager.activate("c".into(), None, None, 1, 1).unwrap();

    // Bounds check
    assert!(matches!(manager.pause(1), Err(ShadowMeshError::InvalidDuration)));
    assert!(matches!(manager.pause(60), Err(ShadowMeshError::InvalidDuration)));

    // Success
    manager.pause(10).unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::Paused);
}

#[test]
fn test_node_cache_hit_miss_counters() {
    let cache = NodeCache::new(5, 60);
    assert_eq!(cache.hit_rate(), 0.0);

    let node = VPNNode {
        id: "n".into(),
        name: "n".into(),
        region: "r".into(),
        country: "c".into(),
        endpoint: "e".into(),
        public_key: "p".into(),
        load: 0,
        latency: 0,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };
    cache.put(node);

    cache.get("n".into()); // hit
    cache.get("missing".into()); // miss

    assert_eq!(cache.hit_rate(), 0.5);
}
