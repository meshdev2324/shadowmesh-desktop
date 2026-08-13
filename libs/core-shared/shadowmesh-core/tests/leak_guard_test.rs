use shadowmesh_core::network::leak_guard::LeakGuard;
use std::fs;

#[test]
fn test_leak_guard_initialization() {
    let settings_path = "test_settings.json";
    let settings_content = r#"{
        "kill_switch_enabled": true,
        "dns_leak_protection": true,
        "emergency_recovery_enabled": true,
        "dns_servers": ["1.1.1.1"]
    }"#;
    fs::write(settings_path, settings_content).unwrap();

    let settings: shadowmesh_core::UserSettings = serde_json::from_str(settings_content).unwrap();
    let guard = LeakGuard::new(settings);
    // Note: We test the initialization logic here.
    // Firewall application requires root, so we verify state.
    assert!(guard.new_settings_loaded());

    fs::remove_file(settings_path).unwrap();
}
