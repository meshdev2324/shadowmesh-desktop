use shadowmesh_core::vpn_manager::{ConnectionStatus, TrafficMode, VPNManager};
use shadowmesh_core::{get_default_user_settings, get_mock_nodes};

#[tokio::test]
async fn test_multi_phase_failover_escalation() {
    let settings = get_default_user_settings();
    let manager = VPNManager::new(settings);
    manager.activate("test-code".into(), None, None, 1, 30).unwrap();

    let node = get_mock_nodes().first().unwrap().clone();
    manager.set_selected_node(node.clone());

    // Phase 1: Normal -> Fragmented
    manager.set_traffic_mode(TrafficMode::Normal);
    manager.trigger_failover().await.unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingFragmented);

    // Phase 2: Fragmented -> REALITY
    manager.trigger_failover().await.unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::ConnectingReality);
}
