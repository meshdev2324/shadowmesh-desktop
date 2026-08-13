use serde::{Deserialize, Serialize};

/// Persistent user settings for the ShadowMesh client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    /// Whether the system-wide kill switch is enabled.
    pub kill_switch_enabled: bool,
    /// Whether DNS leak protection is active.
    pub dns_leak_protection: bool,
    /// Whether emergency network recovery is permitted.
    pub emergency_recovery_enabled: bool,
    /// A list of preferred DNS server addresses.
    pub dns_servers: Vec<String>,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            kill_switch_enabled: false,
            dns_leak_protection: true,
            emergency_recovery_enabled: true,
            dns_servers: vec!["10.8.0.1".to_string()],
        }
    }
}
