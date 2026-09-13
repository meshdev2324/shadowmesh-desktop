use super::*;
use crate::vpn_manager::{TrafficMode, VPNManager};

#[test]
fn test_team_mandatory_stealth_enforcement() {
    let settings = UserSettings::default();
    let manager = VPNManager::new(settings);

    // 1. Activate as Team
    manager
        .activate(
            "TEAM-KEY".to_string(),
            Some("token".to_string()),
            Some("team".to_string()),
            30,
            30,
        )
        .unwrap();

    let node = VPNNode {
        id: "node-1".to_string(),
        name: "Test Node".to_string(),
        region: "us".to_string(),
        country: "US".to_string(),
        endpoint: "1.1.1.1:51820".to_string(),
        public_key: "key".to_string(),
        load: 0,
        latency: 0,
        is_online: true, shard_id: None,
    };

    // 2. Initiate connection - Should force stealth modes despite Normal being default
    manager.initiate_connection(node.clone(), "pubkey".to_string()).unwrap();

    let mode = manager.get_current_connection_mode().unwrap();
    assert!(matches!(mode, TrafficMode::Fragmented | TrafficMode::Reality));
}

#[test]
fn test_granular_usage_tracking_in_manager() {
    let settings = UserSettings::default();
    let manager = VPNManager::new(settings);

    // 1. Set mode to Fragmented (Quantum)
    manager.set_traffic_mode(TrafficMode::Fragmented);

    // 2. Update stats
    let stats1 = ConnectionStats {
        bytes_received: 1000,
        bytes_sent: 500,
        packets_received: 10,
        packets_sent: 5,
        last_handshake: 0,
        connected_since: 0,
    };
    manager.set_stats(stats1);

    let p_stats = manager.get_protocol_stats();
    assert_eq!(p_stats.quantum_sent, 500);
    assert_eq!(p_stats.quantum_received, 1000);

    // 3. Update stats again (incremental)
    let stats2 = ConnectionStats {
        bytes_received: 2500,
        bytes_sent: 1200,
        packets_received: 20,
        packets_sent: 12,
        last_handshake: 0,
        connected_since: 0,
    };
    manager.set_stats(stats2);

    let p_stats = manager.get_protocol_stats();
    assert_eq!(p_stats.quantum_sent, 1200);
    assert_eq!(p_stats.quantum_received, 2500);

    // 4. Switch to Reality and update
    manager.set_traffic_mode(TrafficMode::Reality);
    let stats3 = ConnectionStats {
        bytes_received: 3000,
        bytes_sent: 1500,
        packets_received: 25,
        packets_sent: 15,
        last_handshake: 0,
        connected_since: 0,
    };
    manager.set_stats(stats3);

    let p_stats = manager.get_protocol_stats();
    assert_eq!(p_stats.quantum_sent, 1200); // Should not change
    assert_eq!(p_stats.reality_sent, 300); // 1500 - 1200
    assert_eq!(p_stats.reality_received, 500); // 3000 - 2500
}
