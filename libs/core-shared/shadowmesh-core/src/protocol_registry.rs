//! Typed protocol registry (RFC-012 G4).
//!
//! The engine used to hand-dispatch on `protocol.as_str()` through **four**
//! parallel `match` chains — `Config::validate_strict` (one per direction) and
//! `ShadowMeshSystem::init_outbounds` / `init_inbounds`. Four lists that must
//! agree is the failure mode G4 exists to remove: they had already drifted
//! (see [`BUILTIN`]), and "adding a protocol" meant editing all of them.
//!
//! This module is the single table. Every protocol is one [`ProtocolSpec`]
//! entry: its tag, its aliases, its strict settings parser, and its
//! constructors. Adding a protocol is one typed settings struct plus one entry
//! in [`BUILTIN`] — zero match edits, because there is no longer a match to
//! edit.
//!
//! ## Why a `const` table and not `inventory::submit!`
//!
//! RFC-012 §4.1 sketches `inventory::submit!`. That was not adopted, and the
//! reason is mechanical rather than aesthetic:
//!
//! * `inventory` registers through a `#[link_section]` + `#[used]` static and
//!   a linker-emitted constructor. This crate builds as
//!   `crate-type = ["rlib", "cdylib"]` for uniffi and is cross-compiled to
//!   `aarch64-linux-android` / `x86_64-linux-android`; linker-section
//!   collection is exactly the mechanism that goes missing across custom
//!   linkers, LTO and NDK toolchains — and it fails *silently*, by dropping
//!   entries. A registry that silently drops a protocol is the
//!   capability-hiding failure this RFC exists to remove, so trading a
//!   compile-time-checked table for it is a downgrade.
//! * It would add a supply-chain dependency to a GPL-sensitive tree for zero
//!   behavioural gain. Every protocol registered here lives in this one
//!   crate; cross-crate registration is not a use case ShadowMesh has.
//!
//! A `const` slice is checked by the compiler, is deterministic in iteration
//! order, and costs nothing at runtime. It satisfies the RFC's actual claim —
//! *"one struct + one registry entry, zero match edits"* — literally.
//!
//! ## Strictness is preserved, not weakened
//!
//! RFC-012's typed-settings work is unchanged: every settings struct is still
//! `deny_unknown_fields`, so a typo is a hard config error. Validation here
//! *is* that parse — [`ProtocolRegistry::validate`] runs each spec's
//! `validate` and nothing else, and a protocol the table does not know is a
//! hard error in both directions. No path in this module can fall back to a
//! default: the old `warn!("... not yet supported, using direct")` arm was
//! unreachable *and* wrong (it would have routed traffic in the clear), and it
//! is gone.
//!
//! ## One intentional behaviour change
//!
//! `tuic` appeared in `init_outbounds`/`init_inbounds` but **not** in
//! `validate_strict`, which runs first — so the TUIC arms were dead code and
//! `TuicSettings`/`TuicInboundSettings` were unreachable. One table cannot
//! reproduce that split, so TUIC now validates and constructs. See
//! `tests::tuic_became_reachable` for the pin.

use crate::config::settings;
use crate::config::{Config, InboundConfig, OutboundConfig};
use crate::engine::actor::EngineHandle;
use crate::transport::hysteria::HysteriaInbound;
use crate::transport::inbound::tls_util;
use crate::transport::inbound::tun::TunInbound;
use crate::transport::inbound::{
    HttpInbound, ShadowsocksInbound, SocksInbound, TrojanInbound, TuicInbound, VlessInbound,
    VmessInbound,
};
use crate::transport::outbound::trojan::TlsClientParams;
use crate::transport::outbound::{
    DirectOutbound, ShadowsocksOutbound, TrojanOutbound, TuicOutbound, VlessOutbound,
    VmessOutbound, WireguardOutbound,
};
use crate::transport::traits::{InboundListener, OutboundDialer};
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// What an inbound constructor produced.
pub enum InboundPlan {
    /// Register this listener with the lifecycle manager.
    Register(Arc<dyn InboundListener>),
    /// The protocol is configured but yields no listener.
    ///
    /// Preserved verbatim from the `tun` arm of the old match chain, which
    /// registered nothing when the entry carried no `settings` block. It is
    /// the one legitimate "nothing to do" answer; an *unknown* protocol is
    /// never this — it is a hard error. `init_inbounds` logs a warning
    /// naming the tag when it happens, so a listener that is not listening
    /// cannot be invisible.
    Skip,
}

/// What an inbound constructor needs.
pub struct InboundRequest<'a> {
    pub tag: &'a str,
    /// The tag as written in the config, for error messages — an alias and
    /// its canonical spelling must report what the operator typed.
    pub protocol: &'a str,
    /// Resolved from the entry plus the spec's protocol defaults, so a
    /// constructor never re-implements them.
    pub listen_addr: String,
    /// `None` only for a spec that declares no settings block and whose entry
    /// omitted one.
    pub settings: Option<&'a serde_json::Value>,
    pub engine: &'a EngineHandle,
}

/// What an outbound constructor needs.
pub struct OutboundRequest<'a> {
    pub tag: &'a str,
    pub protocol: &'a str,
    pub settings: &'a serde_json::Value,
}

/// The outbound half of a protocol: strict parser + constructor.
#[derive(Clone, Copy)]
pub struct OutboundSpec {
    /// Strict typed-settings parse. Every outbound has one — including
    /// `direct`, whose empty struct still rejects unknown keys.
    pub validate: fn(&serde_json::Value, &str) -> Result<()>,
    pub build: fn(&OutboundRequest<'_>) -> Result<Arc<dyn OutboundDialer>>,
}

/// The inbound half of a protocol.
#[derive(Clone, Copy)]
pub struct InboundSpec {
    /// Applied when the config entry omits `listen` / `port`.
    pub default_listen: &'static str,
    pub default_port: u16,
    /// `None` ⇒ the protocol declares no settings block: `socks`/`http` read
    /// none, and `tun` keeps its legacy raw settings (RFC-012 G4 does not
    /// retro-fit a schema to it, which would start rejecting configs that
    /// boot today).
    pub validate: Option<fn(&serde_json::Value, &str) -> Result<()>>,
    pub build: fn(&InboundRequest<'_>) -> Result<InboundPlan>,
}

/// One protocol. Adding one is one struct plus one entry in [`BUILTIN`].
#[derive(Clone, Copy)]
pub struct ProtocolSpec {
    /// Canonical tag as written in `config.json`.
    pub tag: &'static str,
    /// Alternative spellings that resolve to this spec.
    pub aliases: &'static [&'static str],
    pub outbound: Option<OutboundSpec>,
    pub inbound: Option<InboundSpec>,
}

/// The protocol table.
///
/// Outbound support: `direct` (`freedom`), `shadowsocks`, `trojan`, `vless`,
/// `vmess`, `wireguard`, `tuic`.
/// Inbound support: `socks`, `http`, `tun`, `trojan`, `shadowsocks`, `vless`,
/// `vmess`, `hysteria`, `tuic`.
pub static BUILTIN: &[ProtocolSpec] = &[
    // ---- local, settings-less listeners ----------------------------------
    ProtocolSpec {
        tag: "socks",
        aliases: &[],
        outbound: None,
        inbound: Some(InboundSpec {
            default_listen: "127.0.0.1",
            default_port: 1080,
            validate: None,
            build: |r| {
                Ok(InboundPlan::Register(Arc::new(SocksInbound::new(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    r.engine.clone(),
                ))))
            },
        }),
    },
    ProtocolSpec {
        tag: "http",
        aliases: &[],
        outbound: None,
        inbound: Some(InboundSpec {
            default_listen: "127.0.0.1",
            default_port: 8080,
            validate: None,
            build: |r| {
                Ok(InboundPlan::Register(Arc::new(HttpInbound::new(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    r.engine.clone(),
                ))))
            },
        }),
    },
    ProtocolSpec {
        tag: "tun",
        aliases: &[],
        outbound: None,
        inbound: Some(InboundSpec {
            // `tun` reads no listen/port; the defaults exist only so the
            // resolved address is well-formed when one is needed.
            default_listen: "127.0.0.1",
            default_port: 0,
            validate: None,
            build: |r| {
                // Legacy raw settings, preserved exactly: an entry with no
                // `settings` block registers no TUN device, as before.
                let Some(s) = r.settings else {
                    return Ok(InboundPlan::Skip);
                };
                Ok(InboundPlan::Register(Arc::new(TunInbound::new(
                    r.tag.to_string(),
                    s["name"].as_str().unwrap_or("utun0").to_string(),
                    s["address"].as_str().unwrap_or("198.18.0.1").to_string(),
                    s["netmask"].as_str().unwrap_or("255.255.255.0").to_string(),
                    r.engine.clone(),
                ))))
            },
        }),
    },
    // ---- direct ----------------------------------------------------------
    ProtocolSpec {
        tag: "direct",
        aliases: &["freedom"],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::DirectSettings>,
            build: |r| {
                settings::parse_strict::<settings::DirectSettings>(r.settings, r.protocol)?;
                Ok(Arc::new(DirectOutbound::new(r.tag.to_string())) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: None,
    },
    // ---- shadowsocks (SIP007 AEAD / SS2022) ------------------------------
    ProtocolSpec {
        tag: "shadowsocks",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::ShadowsocksSettings>,
            build: |r| {
                let s = settings::parse_strict::<settings::ShadowsocksSettings>(
                    r.settings, r.protocol,
                )?;
                // RFC-012 G5: `padding` is config-gated and defaults off, so
                // an existing config file keeps the exact SIP007 wire.
                let padding = settings::padding_mode(s.padding);
                Ok(Arc::new(ShadowsocksOutbound::with_padding(
                    r.tag.to_string(),
                    s.server,
                    s.port,
                    s.method,
                    s.password,
                    padding,
                )?) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 8388,
            validate: Some(parse_only::<settings::ShadowsocksInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::ShadowsocksInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                // RFC-012 G5: mirror of the outbound gate. Both ends must
                // agree — a padded stream read by an unpadded listener (or
                // the reverse) is a protocol error, not a degradation.
                let padding = settings::padding_mode(s.padding);
                Ok(InboundPlan::Register(Arc::new(ShadowsocksInbound::with_padding(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    s.method,
                    s.password,
                    r.engine.clone(),
                    padding,
                )?)))
            },
        }),
    },
    // ---- trojan ----------------------------------------------------------
    ProtocolSpec {
        tag: "trojan",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::TrojanSettings>,
            build: |r| {
                let s = settings::parse_strict::<settings::TrojanSettings>(r.settings, r.protocol)?;
                let tls = s.tls.map(|t| TlsClientParams { sni: t.sni, insecure: t.insecure });
                Ok(Arc::new(TrojanOutbound::with_tls(
                    r.tag.to_string(),
                    s.server,
                    s.port,
                    &s.password,
                    tls,
                )) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 443,
            validate: Some(parse_only::<settings::TrojanInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::TrojanInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                let tls = match &s.tls {
                    Some(t) => Some(
                        tls_util::build_server_acceptor(&t.cert_path, &t.key_path)
                            .map_err(|e| anyhow!("inbound '{}' TLS setup failed: {e:#}", r.tag))?,
                    ),
                    None => None,
                };
                Ok(InboundPlan::Register(Arc::new(TrojanInbound::with_tls(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    &s.password,
                    r.engine.clone(),
                    tls,
                ))))
            },
        }),
    },
    // ---- vless -----------------------------------------------------------
    ProtocolSpec {
        tag: "vless",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::VlessSettings>,
            build: |r| {
                let s = settings::parse_strict::<settings::VlessSettings>(r.settings, r.protocol)?;
                let reality = s.reality.filter(|x| x.enabled).map(|x| {
                    crate::RealityConfig::new(
                        s.server.clone(),
                        s.port as u32,
                        s.uuid.clone(),
                        x.public_key,
                        x.short_id,
                        x.sni,
                        x.fingerprint,
                    )
                });
                Ok(Arc::new(VlessOutbound::new(
                    r.tag.to_string(),
                    s.server,
                    s.port,
                    &s.uuid,
                    s.flow,
                    reality,
                )?) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 443,
            validate: Some(parse_only::<settings::VlessInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::VlessInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                let reality = s.reality.map(|x| crate::RealityServerConfig {
                    private_key: x.private_key,
                    short_ids: x.short_ids,
                    sni_target: x.sni_target,
                    server_names: x.server_names,
                });
                Ok(InboundPlan::Register(Arc::new(VlessInbound::new(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    &s.uuid,
                    r.engine.clone(),
                    reality,
                    s.decoy,
                )?)))
            },
        }),
    },
    // ---- vmess -----------------------------------------------------------
    ProtocolSpec {
        tag: "vmess",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::VmessSettings>,
            build: |r| {
                let s = settings::parse_strict::<settings::VmessSettings>(r.settings, r.protocol)?;
                let security = s.security.unwrap_or_else(|| "auto".to_string());
                // RFC-012 G5: config-gated, defaults off, so an existing
                // config file keeps the exact pre-G5 wire.
                let padding = settings::padding_mode(s.padding);
                Ok(Arc::new(VmessOutbound::with_padding(
                    r.tag.to_string(),
                    s.server,
                    s.port,
                    &s.uuid,
                    security,
                    padding,
                )?) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 443,
            validate: Some(parse_only::<settings::VmessInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::VmessInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                // RFC-012 G5: mirror of the outbound gate.
                let padding = settings::padding_mode(s.padding);
                Ok(InboundPlan::Register(Arc::new(VmessInbound::with_padding(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    &s.uuid,
                    r.engine.clone(),
                    padding,
                )?)))
            },
        }),
    },
    // ---- wireguard (outbound only) ---------------------------------------
    ProtocolSpec {
        tag: "wireguard",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::WireGuardSettings>,
            build: |r| {
                let s =
                    settings::parse_strict::<settings::WireGuardSettings>(r.settings, r.protocol)?;
                Ok(Arc::new(WireguardOutbound::new(
                    r.tag.to_string(),
                    s.endpoint,
                    s.private_key,
                    s.public_key,
                )) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: None,
    },
    // ---- hysteria (inbound only; QUIC egress is not implemented) ---------
    ProtocolSpec {
        tag: "hysteria",
        aliases: &[],
        outbound: None,
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 36712,
            validate: Some(parse_only::<settings::HysteriaInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::HysteriaInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                Ok(InboundPlan::Register(Arc::new(HysteriaInbound::new(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    s.password,
                    Some(s.cert_path),
                    Some(s.key_path),
                    r.engine.clone(),
                ))))
            },
        }),
    },
    // ---- tuic (RFC-023) --------------------------------------------------
    ProtocolSpec {
        tag: "tuic",
        aliases: &[],
        outbound: Some(OutboundSpec {
            validate: parse_only::<settings::TuicSettings>,
            build: |r| {
                let s = settings::parse_strict::<settings::TuicSettings>(r.settings, r.protocol)?;
                Ok(Arc::new(TuicOutbound::new(
                    r.tag.to_string(),
                    s.server,
                    s.port,
                    &s.uuid,
                    &s.password,
                    s.sni,
                    s.insecure,
                )?) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "0.0.0.0",
            default_port: 8443,
            validate: Some(parse_only::<settings::TuicInboundSettings>),
            build: |r| {
                let s = settings::parse_strict::<settings::TuicInboundSettings>(
                    r.settings.unwrap_or(&serde_json::Value::Null),
                    r.protocol,
                )?;
                Ok(InboundPlan::Register(Arc::new(TuicInbound::new(
                    r.tag.to_string(),
                    r.listen_addr.clone(),
                    &s.uuid,
                    &s.password,
                    s.cert_path,
                    s.key_path,
                    r.engine.clone(),
                )?)))
            },
        }),
    },
];

/// A resolver over [`ProtocolSpec`]s.
///
/// The table is a `Vec` so a caller — chiefly the test that proves G4's claim
/// — can extend the builtin set with a protocol that ships nowhere else.
/// Lookup is a linear scan: the table holds ten entries and is consulted once
/// per config entry at load, so an index would buy nothing and would make
/// extension a second code path.
#[derive(Clone)]
pub struct ProtocolRegistry {
    specs: Vec<ProtocolSpec>,
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl ProtocolRegistry {
    /// Every protocol the engine ships.
    pub fn builtin() -> Self {
        Self { specs: BUILTIN.to_vec() }
    }

    /// A registry over exactly these specs — the extension seam.
    pub fn from_specs(specs: Vec<ProtocolSpec>) -> Self {
        Self { specs }
    }

    /// This registry plus one more protocol.
    pub fn with(mut self, spec: ProtocolSpec) -> Self {
        self.specs.push(spec);
        self
    }

    pub fn specs(&self) -> &[ProtocolSpec] {
        &self.specs
    }

    /// Resolve a tag or alias to its spec.
    pub fn get(&self, protocol: &str) -> Option<&ProtocolSpec> {
        self.specs.iter().find(|s| s.tag == protocol || s.aliases.contains(&protocol))
    }

    /// Canonical tags, in table order — the supported-protocol list an
    /// operator should be pointed at when a config names something unknown.
    pub fn tags(&self) -> Vec<&'static str> {
        self.specs.iter().map(|s| s.tag).collect()
    }

    /// RFC-012 G4 strict validation over every inbound and outbound, without
    /// constructing the runtime. Unknown fields, typos and missing required
    /// keys are hard errors naming the offending field; an unknown protocol is
    /// a hard error in both directions.
    pub fn validate(&self, config: &Config) -> Result<()> {
        for o in &config.outbounds {
            let raw = o.settings.as_ref().ok_or_else(|| {
                anyhow!("outbound '{}' ({}) is missing settings", o.tag, o.protocol)
            })?;
            let spec = self.require_outbound(&o.protocol, &o.tag)?;
            (spec.outbound.as_ref().expect("require_outbound yields an outbound").validate)(
                raw,
                &o.protocol,
            )?;
        }

        for i in &config.inbounds {
            let spec = self.get(&i.protocol).ok_or_else(|| {
                anyhow!("inbound '{}' uses unsupported protocol '{}'", i.tag, i.protocol)
            })?;
            let inbound = spec.inbound.as_ref().ok_or_else(|| {
                anyhow!(
                    "inbound '{}' uses protocol '{}', which has no inbound listener",
                    i.tag,
                    i.protocol
                )
            })?;
            // A spec without a parser declares no settings block (`socks`,
            // `http`, `tun`) — the entry is accepted as-is, exactly as before.
            if let Some(validate) = inbound.validate {
                let raw = i.settings.as_ref().ok_or_else(|| {
                    anyhow!("inbound '{}' ({}) is missing settings", i.tag, i.protocol)
                })?;
                validate(raw, &i.protocol)?;
            }
        }

        Ok(())
    }

    /// Build the dialer for one outbound entry.
    pub fn build_outbound(&self, cfg: &OutboundConfig) -> Result<Arc<dyn OutboundDialer>> {
        let raw = cfg.settings.as_ref().ok_or_else(|| {
            anyhow!("outbound '{}' ({}) is missing settings", cfg.tag, cfg.protocol)
        })?;
        let spec = self.require_outbound(&cfg.protocol, &cfg.tag)?;
        let outbound = spec.outbound.as_ref().expect("require_outbound yields an outbound");
        (outbound.build)(&OutboundRequest { tag: &cfg.tag, protocol: &cfg.protocol, settings: raw })
    }

    /// Build the listener plan for one inbound entry.
    pub fn build_inbound(&self, cfg: &InboundConfig, engine: &EngineHandle) -> Result<InboundPlan> {
        let spec = self.get(&cfg.protocol).ok_or_else(|| {
            anyhow!("inbound '{}' uses unsupported protocol '{}'", cfg.tag, cfg.protocol)
        })?;
        let inbound = spec.inbound.as_ref().ok_or_else(|| {
            anyhow!(
                "inbound '{}' uses protocol '{}', which has no inbound listener",
                cfg.tag,
                cfg.protocol
            )
        })?;

        // A settings-taking inbound must be given one. The old chain
        // resolved this per arm; the table makes it a property of the spec,
        // so a new protocol cannot forget it.
        if inbound.validate.is_some() && cfg.settings.is_none() {
            return Err(anyhow!("inbound '{}' ({}) is missing settings", cfg.tag, cfg.protocol));
        }

        let listen_addr = format!(
            "{}:{}",
            cfg.listen.as_deref().unwrap_or(inbound.default_listen),
            cfg.port.unwrap_or(inbound.default_port)
        );

        (inbound.build)(&InboundRequest {
            tag: &cfg.tag,
            protocol: &cfg.protocol,
            listen_addr,
            settings: cfg.settings.as_ref(),
            engine,
        })
    }

    fn require_outbound<'a>(&'a self, protocol: &str, tag: &str) -> Result<&'a ProtocolSpec> {
        let spec = self.get(protocol).ok_or_else(|| {
            anyhow!("outbound '{}' uses unsupported protocol '{}'", tag, protocol)
        })?;
        if spec.outbound.is_none() {
            return Err(anyhow!(
                "outbound '{}' uses protocol '{}', which has no outbound dialer",
                tag,
                protocol
            ));
        }
        Ok(spec)
    }
}

/// Strict parse, discarding the value: the validator half of a spec.
fn parse_only<T: serde::de::DeserializeOwned>(
    raw: &serde_json::Value,
    protocol: &str,
) -> Result<()> {
    settings::parse_strict::<T>(raw, protocol).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DummySettings {
        marker: String,
    }

    fn engine() -> EngineHandle {
        let (tx, _rx) = async_channel::bounded::<crate::engine::events::EngineEvent>(1);
        EngineHandle::new(tx)
    }

    /// A protocol that ships nowhere else, added at runtime.
    fn registry_with_dummy() -> ProtocolRegistry {
        ProtocolRegistry::builtin().with(ProtocolSpec {
            tag: "dummy-probe",
            aliases: &["dummy-alias"],
            outbound: Some(OutboundSpec {
                validate: parse_only::<DummySettings>,
                build: |r| {
                    let s = settings::parse_strict::<DummySettings>(r.settings, r.protocol)?;
                    // Proof the constructor ran with the typed value in hand.
                    assert_eq!(s.marker, "reachable", "typed settings reached the builder");
                    Ok(Arc::new(DirectOutbound::new(r.tag.to_string())) as Arc<dyn OutboundDialer>)
                },
            }),
            inbound: None,
        })
    }

    #[test]
    fn an_added_protocol_is_reachable_with_no_table_edit() {
        let reg = registry_with_dummy();
        assert_eq!(reg.get("dummy-probe").map(|s| s.tag), Some("dummy-probe"));
        assert!(reg.get("dummy-alias").is_some(), "aliases resolve too");
        assert!(reg.tags().contains(&"dummy-probe"), "it is a first-class tag");

        let cfg = OutboundConfig {
            tag: "probe".into(),
            protocol: "dummy-probe".into(),
            settings: Some(serde_json::json!({ "marker": "reachable" })),
        };
        let dialer = reg.build_outbound(&cfg).expect("new protocol builds");
        assert_eq!(dialer.tag(), "probe");
    }

    #[test]
    fn an_added_protocol_participates_in_strict_validation() {
        let reg = registry_with_dummy();
        let routing =
            crate::config::RoutingConfig { rules: vec![], default_outbound: "probe".into() };
        let dns =
            crate::config::DnsConfig { servers: vec![], fake_ip: None, execution_model: None };

        let good = Config {
            inbounds: vec![],
            outbounds: vec![OutboundConfig {
                tag: "probe".into(),
                protocol: "dummy-alias".into(),
                settings: Some(serde_json::json!({ "marker": "reachable" })),
            }],
            routing,
            dns,
            api: None,
        };
        assert!(reg.validate(&good).is_ok(), "the new protocol validates");

        let typo = Config {
            inbounds: vec![],
            outbounds: vec![OutboundConfig {
                tag: "probe".into(),
                protocol: "dummy-probe".into(),
                settings: Some(serde_json::json!({ "markr": "typo" })),
            }],
            routing: crate::config::RoutingConfig {
                rules: vec![],
                default_outbound: "probe".into(),
            },
            dns: crate::config::DnsConfig { servers: vec![], fake_ip: None, execution_model: None },
            api: None,
        };
        assert!(
            reg.validate(&typo).is_err(),
            "a typo'd key on a newly added protocol is still a hard error"
        );
    }

    #[test]
    fn a_dialect_that_only_has_an_inbound_is_rejected_as_an_outbound() {
        // `socks` is registered inbound-only. Naming it as an outbound is a
        // hard error naming the reason, not a silent skip.
        let reg = ProtocolRegistry::builtin();
        let cfg = OutboundConfig {
            tag: "probe".into(),
            protocol: "socks".into(),
            settings: Some(serde_json::json!({})),
        };
        let Err(err) = reg.build_outbound(&cfg) else {
            panic!("socks is not a dialer");
        };
        assert!(format!("{err:#}").contains("no outbound dialer"), "{err:#}");
    }

    #[test]
    fn unknown_protocols_are_a_hard_error_in_both_directions() {
        let reg = ProtocolRegistry::builtin();
        let out = OutboundConfig {
            tag: "probe".into(),
            protocol: "nope".into(),
            settings: Some(serde_json::json!({})),
        };
        assert!(reg.build_outbound(&out).is_err());
        let inbound = InboundConfig {
            tag: "probe".into(),
            protocol: "nope".into(),
            listen: None,
            port: None,
            settings: Some(serde_json::json!({})),
        };
        assert!(
            reg.build_inbound(&inbound, &engine()).is_err(),
            "an unknown inbound protocol must never resolve to a skip"
        );
    }

    #[test]
    fn every_tag_and_alias_in_the_table_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for spec in BUILTIN {
            assert!(seen.insert(spec.tag), "duplicate tag {}", spec.tag);
            for alias in spec.aliases {
                assert!(seen.insert(*alias), "duplicate tag/alias {alias}");
            }
        }
    }

    /// The drift the registry removes, pinned as a fact.
    ///
    /// Before G4, `tuic` was absent from `Config::validate_strict` while
    /// present in both constructor chains — so it could never be reached, and
    /// `TuicSettings`/`TuicInboundSettings` were dead types. One table cannot
    /// reproduce that split.
    #[test]
    fn tuic_became_reachable() {
        let reg = ProtocolRegistry::builtin();
        let spec = reg.get("tuic").expect("tuic is registered");
        assert!(spec.outbound.is_some(), "tuic has an outbound dialer");
        assert!(spec.inbound.is_some(), "tuic has an inbound listener");

        let cfg = OutboundConfig {
            tag: "tuic-out".into(),
            protocol: "tuic".into(),
            settings: Some(serde_json::json!({
                "server": "edge.invalid",
                "port": 443,
                "uuid": uuid::Uuid::new_v4().to_string(),
                "password": hex::encode(crate::secure_random_bytes(16).expect("CSPRNG")),
            })),
        };
        assert!(reg.build_outbound(&cfg).is_ok(), "a well-formed TUIC outbound must compose");
    }

    #[test]
    fn settings_less_inbounds_do_not_require_a_settings_block() {
        let reg = ProtocolRegistry::builtin();
        let engine = engine();
        for protocol in ["socks", "http"] {
            let cfg = InboundConfig {
                tag: "probe".into(),
                protocol: protocol.into(),
                listen: None,
                port: None,
                settings: None,
            };
            assert!(
                matches!(reg.build_inbound(&cfg, &engine), Ok(InboundPlan::Register(_))),
                "'{protocol}' must build with no settings"
            );
        }
    }

    /// `tun` with no settings block registers nothing — preserved from the
    /// old chain, and only reachable through this one protocol.
    #[test]
    fn tun_without_settings_skips_rather_than_registering() {
        let reg = ProtocolRegistry::builtin();
        let cfg = InboundConfig {
            tag: "tun-in".into(),
            protocol: "tun".into(),
            listen: None,
            port: None,
            settings: None,
        };
        assert!(matches!(reg.build_inbound(&cfg, &engine()), Ok(InboundPlan::Skip)));

        let with_settings =
            InboundConfig { settings: Some(serde_json::json!({ "name": "utun9" })), ..cfg };
        assert!(matches!(
            reg.build_inbound(&with_settings, &engine()),
            Ok(InboundPlan::Register(_))
        ));
    }

    #[test]
    fn protocol_defaults_are_applied_per_protocol() {
        let reg = ProtocolRegistry::builtin();
        // socks defaults to loopback:1080, trojan to 0.0.0.0:443 — the two
        // defaults the old chain hard-coded per arm.
        let expected = [("socks", "127.0.0.1:1080"), ("trojan", "0.0.0.0:443")];
        for (protocol, addr) in expected {
            let spec = reg.get(protocol).expect("registered");
            let inbound = spec.inbound.as_ref().expect("inbound half");
            let cfg = InboundConfig {
                tag: "probe".into(),
                protocol: protocol.into(),
                listen: None,
                port: None,
                settings: None,
            };
            // Rebuild the resolved address the same way build_inbound does.
            let resolved = format!(
                "{}:{}",
                cfg.listen.as_deref().unwrap_or(inbound.default_listen),
                cfg.port.unwrap_or(inbound.default_port)
            );
            assert_eq!(resolved, addr, "protocol default listen address");
        }
    }
}
