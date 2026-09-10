use shadowmesh_core::*;

#[test]
fn test_vpn_pause_validation() {
    let settings = get_default_user_settings();
    let manager = create_vpn_manager(settings).unwrap();

    // Must be activated to pause
    let res = manager.pause(10);
    assert!(res.is_err(), "Should not pause if not activated");

    manager.activate("test-code".to_string(), None, None, 1, 1).unwrap();

    // Test bounds
    assert!(manager.pause(4).is_err(), "Should fail for < 5 mins");
    assert!(manager.pause(16).is_err(), "Should fail for > 15 mins");

    // Successful pause
    manager.pause(10).unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::Paused);
    assert!(manager.get_paused_until().is_some());
}

#[test]
fn test_vpn_resume() {
    let settings = get_default_user_settings();
    let manager = create_vpn_manager(settings).unwrap();
    manager.activate("test-code".to_string(), None, None, 1, 1).unwrap();

    manager.pause(10).unwrap();
    assert_eq!(manager.get_status(), ConnectionStatus::Paused);

    manager.resume();
    assert_eq!(manager.get_status(), ConnectionStatus::Disconnected);
    assert!(manager.get_paused_until().is_none());
}

#[test]
fn test_pause_expiry_logic() {
    let settings = get_default_user_settings();
    let manager = create_vpn_manager(settings).unwrap();
    manager.activate("test-code".to_string(), None, None, 1, 1).unwrap();

    // We can't easily wait 5 minutes in a unit test.
    // However, we can test that check_pause_expiry() returns false when NOT expired.
    manager.pause(5).unwrap();
    assert!(!manager.check_pause_expiry());
    assert_eq!(manager.get_status(), ConnectionStatus::Paused);
}
