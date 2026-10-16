//! Behaviour pins for the protocol dispatch paths (RFC-012 G4).
//!
//! These tests deliberately use ONLY the public API that exists before and
//! after the registry refactor — [`Config::validate_strict`] and
//! [`ShadowMeshSystem::new`] — so the same file compiles and runs against the
//! old match chains and the new registry. That is what makes the refactor
//! provable: every assertion here is about *observable behaviour*, never about
//! how the dispatch is written.
//!
//! What is pinned:
//!   * every supported protocol's settings schema (valid ⇒ accepted,
//!     typo'd key / wrong type / missing key ⇒ hard error),
//!   * `freedom` as an alias of `direct`,
//!   * constructor-level rejection that only the builder can see (an invalid
//!     UUID, an unknown Shadowsocks method),
//!   * unknown and settings-less protocols failing loudly in both directions.
//!
//! Credentials are generated per run (UUID / CSPRNG hex), never literals —
//! `scripts/ci/scan-credential-literals.sh` must stay at zero blocking.

use shadowmesh_core::config::{Config, DnsConfig, InboundConfig, OutboundConfig, RoutingConfig};
use shadowmesh_core::engine::ShadowMeshSystem;

/// Per-run credential material.
fn rand_password() -> String {
    hex::encode(shadowmesh_core::secure_random_bytes(16).expect("OS CSPRNG"))
}

fn rand_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A config with the given outbounds/inbounds and a `direct` fallback so the
/// routing table always resolves. Nothing binds: `ShadowMeshSystem::new`
/// registers listeners but only `start()` binds sockets, and port 0 keeps even
/// that collision-free.
fn config_with(outbounds: Vec<OutboundConfig>, inbounds: Vec<InboundConfig>) -> Config {
    let mut outbounds = outbounds;
    if !outbounds.iter().any(|o| o.protocol == "direct") {
        outbounds.push(OutboundConfig {
            tag: "direct".into(),
            protocol: "direct".into(),
            settings: Some(serde_json::json!({})),
        });
    }
    Config {
        inbounds,
        outbounds,
        routing: RoutingConfig { rules: vec![], default_outbound: "direct".into() },
        dns: DnsConfig { servers: vec![], fake_ip: None, execution_model: None },
        api: None,
    }
}

fn outbound(tag: &str, protocol: &str, settings: serde_json::Value) -> OutboundConfig {
    OutboundConfig { tag: tag.into(), protocol: protocol.into(), settings: Some(settings) }
}

fn inbound(
    tag: &str,
    protocol: &str,
    port: u16,
    settings: Option<serde_json::Value>,
) -> InboundConfig {
    InboundConfig {
        tag: tag.into(),
        protocol: protocol.into(),
        listen: Some("127.0.0.1".into()),
        port: Some(port),
        settings,
    }
}

/// Well-formed settings for every outbound protocol the engine ships.
fn valid_outbound_settings(protocol: &str) -> serde_json::Value {
    let password = rand_password();
    match protocol {
        "direct" | "freedom" => serde_json::json!({}),
        "shadowsocks" => serde_json::json!({
            "server": "127.0.0.1", "port": 8388,
            "method": "aes-256-gcm", "password": password,
        }),
        "trojan" => serde_json::json!({
            "server": "127.0.0.1", "port": 443, "password": password,
        }),
        "vless" => serde_json::json!({
            "server": "127.0.0.1", "port": 443, "uuid": rand_uuid(),
        }),
        "vmess" => serde_json::json!({
            "server": "127.0.0.1", "port": 443, "uuid": rand_uuid(),
        }),
        "wireguard" => serde_json::json!({
            "endpoint": "127.0.0.1:51820",
            "private_key": rand_password(),
            "public_key": rand_password(),
        }),
        other => panic!("no fixture for outbound protocol '{other}'"),
    }
}

/// Well-formed settings for every inbound protocol the engine ships.
fn valid_inbound_settings(protocol: &str) -> serde_json::Value {
    match protocol {
        "socks" | "http" => serde_json::json!({}),
        "shadowsocks" => serde_json::json!({
            "method": "aes-256-gcm", "password": rand_password(),
        }),
        "trojan" => serde_json::json!({ "password": rand_password() }),
        "vless" => serde_json::json!({ "uuid": rand_uuid() }),
        "vmess" => serde_json::json!({ "uuid": rand_uuid() }),
        "hysteria" => serde_json::json!({
            "password": rand_password(),
            "cert_path": "/nonexistent/edge-hysteria-cert.pem",
            "key_path": "/nonexistent/edge-hysteria-key.pem",
        }),
        other => panic!("no fixture for inbound protocol '{other}'"),
    }
}

const OUTBOUND_PROTOCOLS: &[&str] =
    &["direct", "freedom", "shadowsocks", "trojan", "vless", "vmess", "wireguard"];

const INBOUND_PROTOCOLS: &[&str] =
    &["socks", "http", "shadowsocks", "trojan", "vless", "vmess", "hysteria"];

// ---------------------------------------------------------------------------
// Schema acceptance
// ---------------------------------------------------------------------------

#[test]
fn every_outbound_protocol_accepts_its_own_settings() {
    for protocol in OUTBOUND_PROTOCOLS {
        let cfg = config_with(
            vec![outbound("probe", protocol, valid_outbound_settings(protocol))],
            vec![],
        );
        assert!(
            cfg.validate_strict().is_ok(),
            "valid settings for outbound '{protocol}' must validate"
        );
    }
}

#[test]
fn every_inbound_protocol_accepts_its_own_settings() {
    for protocol in INBOUND_PROTOCOLS {
        let cfg = config_with(
            vec![],
            vec![inbound("probe", protocol, 0, Some(valid_inbound_settings(protocol)))],
        );
        assert!(
            cfg.validate_strict().is_ok(),
            "valid settings for inbound '{protocol}' must validate"
        );
    }
}

#[test]
fn freedom_is_an_alias_of_direct() {
    let cfg = config_with(vec![outbound("probe", "freedom", serde_json::json!({}))], vec![]);
    assert!(cfg.validate_strict().is_ok(), "freedom must resolve like direct");
}

// ---------------------------------------------------------------------------
// Schema rejection — the RFC-012 G4 strictness contract
// ---------------------------------------------------------------------------

/// Outbound protocols that declare a non-empty schema, so emptying the
/// settings block removes at least one required key.
const SCHEMA_BEARING_OUTBOUNDS: &[&str] = &["shadowsocks", "trojan", "vless", "vmess", "wireguard"];

/// Inbound protocols whose spec declares a settings parser. `socks`, `http`
/// and `tun` deliberately declare none — an unknown key there is not a typo
/// in anything the engine reads, so it is not a hard error. That is the
/// pre-existing contract, preserved.
const SCHEMA_BEARING_INBOUNDS: &[&str] = &["shadowsocks", "trojan", "vless", "vmess", "hysteria"];

#[test]
fn a_typoed_outbound_key_is_rejected_for_every_protocol() {
    for protocol in OUTBOUND_PROTOCOLS {
        let mut settings = valid_outbound_settings(protocol);
        settings["definitely_not_a_real_key"] = serde_json::json!("x");
        let cfg = config_with(vec![outbound("probe", protocol, settings)], vec![]);
        assert!(
            cfg.validate_strict().is_err(),
            "a typo'd key must be a hard error for outbound '{protocol}'"
        );
    }
}

#[test]
fn a_typoed_inbound_key_is_rejected_for_every_schema_bearing_protocol() {
    for protocol in SCHEMA_BEARING_INBOUNDS {
        let mut settings = valid_inbound_settings(protocol);
        settings["definitely_not_a_real_key"] = serde_json::json!("x");
        let cfg = config_with(vec![], vec![inbound("probe", protocol, 0, Some(settings))]);
        assert!(
            cfg.validate_strict().is_err(),
            "a typo'd key must be a hard error for inbound '{protocol}'"
        );
    }
}

#[test]
fn settings_less_inbounds_accept_an_unknown_key() {
    // The other side of the same coin, pinned so it cannot drift silently:
    // `socks`/`http`/`tun` read no settings, so they neither require nor
    // police one. Adding a schema later is a deliberate change, not a fix.
    for protocol in ["socks", "http"] {
        let cfg = config_with(
            vec![],
            vec![inbound("probe", protocol, 0, Some(serde_json::json!({ "whatever": 1 })))],
        );
        assert!(
            cfg.validate_strict().is_ok(),
            "'{protocol}' declares no settings block, so an unknown key is inert"
        );
    }
}

#[test]
fn a_missing_required_outbound_key_is_rejected_for_every_protocol() {
    for protocol in SCHEMA_BEARING_OUTBOUNDS {
        let cfg = config_with(vec![outbound("probe", protocol, serde_json::json!({}))], vec![]);
        assert!(
            cfg.validate_strict().is_err(),
            "missing required keys must be a hard error for outbound '{protocol}'"
        );
    }
}

#[test]
fn a_wrongly_typed_outbound_key_is_rejected() {
    for protocol in OUTBOUND_PROTOCOLS {
        // Rewrite every present key to a wrong type (an array where a string
        // / number / object belongs). `direct`/`freedom` have no keys, so an
        // unknown key is the only way to make their object invalid.
        let mut settings = valid_outbound_settings(protocol);
        let Some(map) = settings.as_object_mut() else { panic!("fixture is an object") };
        let keys: Vec<String> = map.keys().cloned().collect();
        if keys.is_empty() {
            map.insert("unexpected".into(), serde_json::json!(["not", "a", "string"]));
        } else {
            for key in keys {
                map.insert(key, serde_json::json!(["not", "a", "string"]));
            }
        }
        let cfg = config_with(vec![outbound("probe", protocol, settings)], vec![]);
        assert!(
            cfg.validate_strict().is_err(),
            "a wrong-typed key must be a hard error for outbound '{protocol}'"
        );
    }
}

#[test]
fn missing_outbound_settings_are_rejected() {
    let cfg = config_with(
        vec![OutboundConfig { tag: "probe".into(), protocol: "trojan".into(), settings: None }],
        vec![],
    );
    assert!(cfg.validate_strict().is_err(), "a settings-less outbound must be a hard error");
}

#[test]
fn missing_inbound_settings_are_rejected() {
    for protocol in ["trojan", "shadowsocks", "vless", "vmess", "hysteria"] {
        let cfg = config_with(vec![], vec![inbound("probe", protocol, 0, None)]);
        assert!(
            cfg.validate_strict().is_err(),
            "a settings-less inbound '{protocol}' must be a hard error"
        );
    }
}

// ---------------------------------------------------------------------------
// Unknown protocols fail loudly, in both directions
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_outbound_protocol_is_a_hard_error() {
    let cfg = config_with(vec![outbound("probe", "not-a-protocol", serde_json::json!({}))], vec![]);
    let err = cfg.validate_strict().expect_err("unknown outbound protocol must fail");
    let text = format!("{err:#}");
    assert!(text.contains("not-a-protocol"), "error must name the protocol: {text}");
    assert!(text.contains("probe"), "error must name the tag: {text}");
}

#[test]
fn an_unknown_inbound_protocol_is_a_hard_error() {
    let cfg = config_with(
        vec![],
        vec![inbound("probe", "not-a-protocol", 0, Some(serde_json::json!({})))],
    );
    let err = cfg.validate_strict().expect_err("unknown inbound protocol must fail");
    let text = format!("{err:#}");
    assert!(text.contains("not-a-protocol"), "error must name the protocol: {text}");
    assert!(text.contains("probe"), "error must name the tag: {text}");
}

// ---------------------------------------------------------------------------
// Constructor-level behaviour: what only the builder can see
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_inbound_protocol_composes_through_the_engine() {
    for protocol in INBOUND_PROTOCOLS {
        let cfg = config_with(
            vec![],
            vec![inbound("probe-in", protocol, 0, Some(valid_inbound_settings(protocol)))],
        );
        let outcome = ShadowMeshSystem::new(cfg).await;
        assert!(outcome.is_ok(), "inbound '{protocol}' must compose: {:?}", outcome.err());
    }
}

#[tokio::test]
async fn every_outbound_protocol_composes_through_the_engine() {
    for protocol in OUTBOUND_PROTOCOLS {
        let cfg = config_with(
            vec![outbound("probe-out", protocol, valid_outbound_settings(protocol))],
            vec![inbound("probe-in", "socks", 0, None)],
        );
        let outcome = ShadowMeshSystem::new(cfg).await;
        assert!(outcome.is_ok(), "outbound '{protocol}' must compose: {:?}", outcome.err());
    }
}

#[tokio::test]
async fn a_valid_uuid_is_parsed_at_composition_not_later() {
    // VlessOutbound/VmessInbound parse the UUID at construction. This pins
    // that the *builder* (not merely the schema) rejects a malformed one.
    let cfg = config_with(
        vec![],
        vec![inbound("probe-in", "vmess", 0, Some(serde_json::json!({ "uuid": "not-a-uuid" })))],
    );
    assert!(
        ShadowMeshSystem::new(cfg).await.is_err(),
        "an unparsable UUID must fail composition, not first dial"
    );
}

#[tokio::test]
async fn an_unknown_shadowsocks_method_is_rejected_at_composition() {
    let cfg = config_with(
        vec![outbound(
            "probe-out",
            "shadowsocks",
            serde_json::json!({
                "server": "127.0.0.1", "port": 8388,
                "method": "not-a-cipher", "password": rand_password(),
            }),
        )],
        vec![inbound("probe-in", "socks", 0, None)],
    );
    assert!(
        ShadowMeshSystem::new(cfg).await.is_err(),
        "an unknown Shadowsocks method must fail composition"
    );
}

#[tokio::test]
async fn an_unknown_inbound_protocol_never_reaches_the_lifecycle() {
    let cfg = config_with(
        vec![],
        vec![inbound("probe-in", "not-a-protocol", 0, Some(serde_json::json!({})))],
    );
    assert!(
        ShadowMeshSystem::new(cfg).await.is_err(),
        "an unknown inbound protocol must not silently register nothing"
    );
}
