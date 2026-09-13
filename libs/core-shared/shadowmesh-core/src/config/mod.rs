use crate::router::rule::{Action, RoutingRule};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Typed per-protocol outbound/inbound settings (RFC-012 G4).
pub mod settings;

/// Level of Quantum Resistance applied to the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuantumResistanceLevel {
    /// No post-quantum protection.
    #[serde(rename = "NONE")]
    NONE,
    /// Hybrid X25519 + ML-KEM (Kyber768) protection.
    #[serde(rename = "HYBRID")]
    HYBRID,
    /// Pure Post-Quantum (Experimental).
    #[serde(rename = "FULL")]
    FULL,
}

/// Persistent user settings for the ShadowMesh client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    /// Desired quantum resistance level.
    pub quantum_level: QuantumResistanceLevel,
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
            quantum_level: QuantumResistanceLevel::NONE,
            kill_switch_enabled: false,
            dns_leak_protection: true,
            emergency_recovery_enabled: true,
            dns_servers: vec!["10.8.0.1".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
    pub api: Option<ApiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub protocol: String,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String,
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
    pub default_outbound: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub fake_ip: Option<FakeIpConfig>,
    pub execution_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub range: String,
    pub max_size: usize,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        let outbound_tags: std::collections::HashSet<_> =
            self.outbounds.iter().map(|o| &o.tag).collect();

        if !outbound_tags.contains(&self.routing.default_outbound) {
            return Err(anyhow!(
                "Default outbound tag '{}' not found in outbounds",
                self.routing.default_outbound
            ));
        }

        for rule in &self.routing.rules {
            if let Action::Route(tag) = &rule.action {
                if !outbound_tags.contains(tag) {
                    return Err(anyhow!(
                        "Outbound tag '{}' in rule '{}' not found in outbounds",
                        tag,
                        rule.tag
                    ));
                }
            }
        }

        Ok(())
    }

    /// RFC-012 G4: strict typed-settings validation over every inbound and
    /// outbound, without constructing the runtime. Unknown fields, typos and
    /// missing required keys are hard errors naming the offending field.
    /// Invoked by `ShadowMeshSystem::new` before composition, and standalone
    /// by `shadowmesh check` for offline validation of edge configs.
    pub fn validate_strict(&self) -> Result<()> {
        use crate::config::settings::{
            self, DirectSettings, HysteriaInboundSettings, ShadowsocksInboundSettings,
            ShadowsocksSettings, TrojanInboundSettings, TrojanSettings, VlessInboundSettings,
            VlessSettings, VmessInboundSettings, VmessSettings, WireGuardSettings,
        };

        for o in &self.outbounds {
            let raw = o.settings.as_ref().ok_or_else(|| {
                anyhow!("outbound '{}' ({}) is missing settings", o.tag, o.protocol)
            })?;
            match o.protocol.as_str() {
                "direct" | "freedom" => {
                    let _: DirectSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                "shadowsocks" => {
                    let _: ShadowsocksSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                "trojan" => {
                    let _: TrojanSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                "vless" => {
                    let _: VlessSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                "vmess" => {
                    let _: VmessSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                "wireguard" => {
                    let _: WireGuardSettings = settings::parse_strict(raw, &o.protocol)?;
                }
                other => {
                    return Err(anyhow!(
                        "outbound '{}' uses unsupported protocol '{other}'",
                        o.tag
                    ));
                }
            }
        }

        for i in &self.inbounds {
            match i.protocol.as_str() {
                // Settings-less local inbounds.
                "socks" | "http" => {}
                // Client-side TUN inbound keeps legacy raw settings.
                "tun" => {}
                "trojan" => {
                    let raw = i.settings.as_ref().ok_or_else(|| {
                        anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                    })?;
                    let _: TrojanInboundSettings = settings::parse_strict(raw, &i.protocol)?;
                }
                "shadowsocks" => {
                    let raw = i.settings.as_ref().ok_or_else(|| {
                        anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                    })?;
                    let _: ShadowsocksInboundSettings = settings::parse_strict(raw, &i.protocol)?;
                }
                "vless" => {
                    let raw = i.settings.as_ref().ok_or_else(|| {
                        anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                    })?;
                    let _: VlessInboundSettings = settings::parse_strict(raw, &i.protocol)?;
                }
                "vmess" => {
                    let raw = i.settings.as_ref().ok_or_else(|| {
                        anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                    })?;
                    let _: VmessInboundSettings = settings::parse_strict(raw, &i.protocol)?;
                }
                "hysteria" => {
                    let raw = i.settings.as_ref().ok_or_else(|| {
                        anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                    })?;
                    let _: HysteriaInboundSettings = settings::parse_strict(raw, &i.protocol)?;
                }
                other => {
                    return Err(anyhow!("inbound '{}' uses unsupported protocol '{other}'", i.tag));
                }
            }
        }

        Ok(())
    }
}
