//! Typed per-protocol settings (RFC-012 G4).
//!
//! Replaces the `serde_json::Value` + `unwrap_or_default()` pattern, which
//! silently defaulted ports/passwords on typos — a security smell. Here an
//! unknown or missing field is a hard config error at load time.
//!
//! Every struct uses `deny_unknown_fields`: a typo like `"passwrd"` fails
//! validation instead of silently producing an empty password.

use serde::Deserialize;

fn default_none<T>() -> Option<T> {
    None
}

/// Settings for the `direct` outbound. No fields — presence is enough.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSettings {}

/// Settings for the `shadowsocks` outbound (SIP007 AEAD).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ShadowsocksSettings {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

/// Settings for the `trojan` outbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct TrojanSettings {
    pub server: String,
    pub port: u16,
    pub password: String,
    /// Optional client TLS (Trojan-GFW mandates TLS on the wire).
    #[serde(default = "default_none")]
    pub tls: Option<TlsClientSettings>,
}

/// Client TLS parameters (RFC-015 §4.4). `insecure = true` accepts
/// self-signed edge certificates — explicit operator choice only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct TlsClientSettings {
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
}

/// REALITY sub-configuration for `vless`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RealitySettings {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
    pub sni: String,
    #[serde(default = "default_none")]
    pub fingerprint: Option<String>,
}

/// Settings for the `vless` outbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct VlessSettings {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub reality: Option<RealitySettings>,
}

/// Settings for the `vmess` outbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct VmessSettings {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default = "default_none")]
    pub security: Option<String>,
}

/// Settings for the `wireguard` outbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardSettings {
    pub endpoint: String,
    pub private_key: String,
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// Server-side (inbound) settings — RFC-012 G4 parity for the edge role.
// Same strictness contract: unknown/missing fields are hard config errors.
// ---------------------------------------------------------------------------

/// Settings for the `shadowsocks` inbound (SIP007 AEAD / SS2022).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksInboundSettings {
    pub method: String,
    pub password: String,
}

/// Settings for the `trojan` inbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanInboundSettings {
    pub password: String,
    /// Optional server-side TLS termination. Trojan-GFW requires TLS on the
    /// wire; omit it only when TLS is terminated by an external front.
    #[serde(default = "default_none")]
    pub tls: Option<TlsServerSettings>,
}

/// PEM file pair for inbound TLS termination.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsServerSettings {
    pub cert_path: String,
    pub key_path: String,
}

/// Server-side REALITY sub-configuration for the `vless` inbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessRealityServerSettings {
    /// Hex-encoded X25519 private key (64 hex chars) — as consumed by
    /// `RealityServerConfig::decrypt_handshake`.
    pub private_key: String,
    /// Allowed short IDs (hex, typically 16 chars = 8 bytes).
    pub short_ids: Vec<String>,
    /// SNI / fallback target the connection is proxied to when REALITY
    /// validation fails (active-probing resistance).
    pub sni_target: String,
}

/// Settings for the `vless` inbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessInboundSettings {
    pub uuid: String,
    /// Plain-text decoy target for non-REALITY fallback proxying
    /// ("host:port" or bare host defaulting to port 443).
    #[serde(default = "default_none")]
    pub decoy: Option<String>,
    #[serde(default = "default_none")]
    pub reality: Option<VlessRealityServerSettings>,
}

/// Settings for the `vmess` inbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessInboundSettings {
    pub uuid: String,
}

/// Settings for the `hysteria` inbound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HysteriaInboundSettings {
    pub password: String,
}

/// Parses raw settings JSON into a strict typed struct. Unknown keys and
/// wrong types are hard errors naming the offending field.
pub fn parse_strict<T: serde::de::DeserializeOwned>(
    raw: &serde_json::Value,
    protocol: &str,
) -> anyhow::Result<T> {
    serde_json::from_value(raw.clone())
        .map_err(|e| anyhow::anyhow!("invalid settings for protocol '{protocol}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_field_typo() {
        let raw = serde_json::json!({
            "server": "1.2.3.4",
            "port": 443,
            "method": "aes-256-gcm",
            "passwrd": "typo!", // typo must FAIL, not silently default
        });
        let r: Result<ShadowsocksSettings, _> = parse_strict(&raw, "shadowsocks");
        assert!(r.is_err(), "typo'd key must be a hard error");
    }

    #[test]
    fn rejects_missing_required_field() {
        let raw = serde_json::json!({ "server": "1.2.3.4" });
        let r: Result<ShadowsocksSettings, _> = parse_strict(&raw, "shadowsocks");
        assert!(r.is_err(), "missing port/method/password must be a hard error");
    }

    #[test]
    fn rejects_wrong_type() {
        let raw = serde_json::json!({
            "server": "1.2.3.4",
            "port": "not-a-number",
            "method": "aes-256-gcm",
            "password": "x",
        });
        let r: Result<ShadowsocksSettings, _> = parse_strict(&raw, "shadowsocks");
        assert!(r.is_err());
    }

    #[test]
    fn accepts_valid_shadowsocks() {
        let raw = serde_json::json!({
            "server": "1.2.3.4",
            "port": 8388,
            "method": "aes-256-gcm",
            "password": "hunter2",
        });
        let s: ShadowsocksSettings = parse_strict(&raw, "shadowsocks").unwrap();
        assert_eq!(s.port, 8388);
        assert_eq!(s.password, "hunter2");
    }

    #[test]
    fn vless_reality_nested_optional() {
        let raw = serde_json::json!({
            "server": "1.2.3.4",
            "port": 443,
            "uuid": "u",
            "flow": "",
            "reality": {
                "enabled": true,
                "public_key": "pbk",
                "short_id": "sid",
                "sni": "www.example.com",
                "fingerprint": "chrome",
            }
        });
        let s: VlessSettings = parse_strict(&raw, "vless").unwrap();
        assert_eq!(s.reality.as_ref().expect("reality").sni, "www.example.com");
        assert_eq!(s.reality.as_ref().unwrap().fingerprint.as_deref(), Some("chrome"));
    }

    #[test]
    fn vless_without_reality_is_valid() {
        let raw = serde_json::json!({
            "server": "1.2.3.4",
            "port": 443,
            "uuid": "u",
        });
        let s: VlessSettings = parse_strict(&raw, "vless").unwrap();
        assert!(s.reality.is_none());
        assert_eq!(s.flow, "");
    }

    // ---- server-side (inbound) settings ----

    #[test]
    fn vless_inbound_with_reality_parses() {
        // 64 hex chars built from random UUIDs — no literal key material.
        let hex64: String = uuid::Uuid::new_v4().simple().to_string()
            + uuid::Uuid::new_v4().simple().to_string().as_str();
        let raw = serde_json::json!({
            "uuid": "01234567-89ab-cdef-0123-456789abcdef",
            "decoy": "www.microsoft.com:443",
            "reality": {
                "private_key": hex64,
                "short_ids": ["0123456789abcdef"],
                "sni_target": "www.microsoft.com:443",
            }
        });
        let s: VlessInboundSettings = parse_strict(&raw, "vless-inbound").unwrap();
        let r = s.reality.expect("reality present");
        assert_eq!(r.short_ids, vec!["0123456789abcdef".to_string()]);
        assert_eq!(s.decoy.as_deref(), Some("www.microsoft.com:443"));
    }

    #[test]
    fn vless_inbound_rejects_unknown_field() {
        let raw = serde_json::json!({ "uuid": "u", "realityy": {} });
        assert!(parse_strict::<VlessInboundSettings>(&raw, "vless-inbound").is_err());
    }

    #[test]
    fn trojan_inbound_tls_block_parses() {
        let raw = serde_json::json!({
            "password": "pw",
            "tls": { "cert_path": "/etc/sm/cert.pem", "key_path": "/etc/sm/key.pem" }
        });
        let s: TrojanInboundSettings = parse_strict(&raw, "trojan-inbound").unwrap();
        assert!(s.tls.is_some(), "tls block present");
    }

    #[test]
    fn trojan_inbound_without_tls_is_valid() {
        let raw = serde_json::json!({ "password": "pw" });
        let s: TrojanInboundSettings = parse_strict(&raw, "trojan-inbound").unwrap();
        assert!(s.tls.is_none());
        assert_eq!(s.password, "pw");
    }

    #[test]
    fn shadowsocks_inbound_rejects_missing_method() {
        let raw = serde_json::json!({ "password": "pw" });
        assert!(parse_strict::<ShadowsocksInboundSettings>(&raw, "shadowsocks-inbound").is_err());
    }
}
