//! RFC-012 G4, proved rather than asserted: *"adding a protocol = one struct
//! + one registry entry, zero match edits."*
//!
//! The registry refactor (531af27) removed the four parallel `match` chains
//! that `Config::validate_strict` / `init_outbounds` / `init_inbounds` used to
//! carry. Deleting those matches is **not** the G4 claim — it is the absence of
//! the thing G4 was complaining about. The claim is about *adding*:
//!
//! > a protocol that exists nowhere in the engine can be made to work by
//! > touching nothing but the registry table.
//!
//! So this file does exactly that. [`probe_spec`] defines a protocol called
//! `g4-probe` that ships in no production file, registers it through the
//! documented extension path (`ProtocolRegistry::with`), and relays live
//! traffic through it via an inbound listener and an outbound dialer defined
//! entirely in this test. If any dispatch path still hand-matched on
//! `protocol.as_str()`, none of this would compose — the engine would reject
//! `g4-probe` as unknown long before the traffic test ran.
//!
//! ## Why this is not what `protocol_registry.rs`'s own tests already prove
//!
//! The in-module tests build an outbound and assert it returns a dialer. They
//! never construct a `ShadowMeshSystem` and never move a byte, so they cannot
//! catch a dispatch path that bypasses the registry entirely — which is the
//! exact failure G4 exists to prevent.
//!
//! ## The guard against silent reintroduction
//!
//! [`a_protocol_added_at_runtime_dials_and_relays_traffic`] is the behavioural
//! half. The structural half is [`the_dispatch_path_contains_no_protocol_match`],
//! which reads the four files that used to hold the chains and fails if a
//! `match` arm keyed on a protocol-name literal reappears. Neither half alone
//! is sufficient: behaviour alone would tolerate a vestigial match nobody
//! calls, and the source guard alone would tolerate a registry that stopped
//! working.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use shadowmesh_core::config::settings::parse_strict;
use shadowmesh_core::config::{Config, DnsConfig, InboundConfig, OutboundConfig, RoutingConfig};
use shadowmesh_core::engine::context::SharedContext;
use shadowmesh_core::engine::events::EngineEvent;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::engine::{context::ConnectionContext, ShadowMeshSystem};
use shadowmesh_core::protocol_registry::{
    InboundPlan, InboundRequest, InboundSpec, OutboundRequest, OutboundSpec, ProtocolRegistry,
    ProtocolSpec,
};
use shadowmesh_core::transport::traits::{AsyncIoStream, InboundListener, OutboundDialer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The tag of a protocol that exists only in this file.
const PROBE: &str = "g4-probe";

// ---------------------------------------------------------------------------
// "One struct" — the probe's typed settings
// ---------------------------------------------------------------------------

/// Typed settings for the probe protocol.
///
/// `deny_unknown_fields` is the contract every shipped protocol's settings
/// struct carries, so the probe carries it too: a typo must be a hard error,
/// not a silent default. That is what makes the probe a fair stand-in for a
/// real addition rather than a specially-permissed test double.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeSettings {
    /// Handshake marker both constructors assert on, proving the *typed*
    /// value reached the builder rather than an untyped blob.
    marker: String,
    /// Upstream the probe outbound dials — same shape as every real proxy
    /// protocol, whose dial target comes from config rather than from the
    /// routed destination (the destination travels inside the tunnel).
    server: String,
    port: u16,
}

fn parse_probe(raw: &serde_json::Value, protocol: &str) -> Result<ProbeSettings> {
    let parsed = parse_strict::<ProbeSettings>(raw, protocol)?;
    if parsed.marker != "g4-probe-live" {
        return Err(anyhow!("probe marker was {:?}", parsed.marker));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// "One registry entry" — the fake transport
// ---------------------------------------------------------------------------

/// Counters proving the probe's constructors actually ran.
static PROBE_OUTBOUND_DIALS: AtomicUsize = AtomicUsize::new(0);
static PROBE_INBOUND_BUILDS: AtomicUsize = AtomicUsize::new(0);

/// A dialer that exists only in this file.
struct ProbeOutbound {
    tag: String,
    server: String,
    port: u16,
}

#[async_trait::async_trait]
impl OutboundDialer for ProbeOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, _context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        PROBE_OUTBOUND_DIALS.fetch_add(1, Ordering::SeqCst);
        let stream = tokio::net::TcpStream::connect((self.server.as_str(), self.port)).await?;
        Ok(Box::new(stream))
    }

    async fn send_packet(
        &self,
        _context: SharedContext,
        _payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // The probe is a TCP protocol and this file never exercises UDP. The
        // trait documents an empty Vec as the fire-and-forget answer for a
        // transport that cannot carry replies.
        Ok(Vec::new())
    }
}

/// A listener that exists only in this file. On `listen()` it accepts one
/// connection, reads a SOCKS-style target-address header, and hands the
/// decrypted stream to the engine as `EngineEvent::NewStream` — the same event
/// every shipped inbound emits.
struct ProbeInbound {
    tag: String,
    listen_addr: String,
    engine: shadowmesh_core::engine::EngineHandle,
}

#[async_trait::async_trait]
impl InboundListener for ProbeInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.listen_addr).await?;
        let (mut socket, _peer) = listener.accept().await?;

        // [atyp][addr][port] — IPv4 only; this is a test fixture, and the
        // client below always sends atyp 1.
        let mut atyp = [0u8; 1];
        socket.read_exact(&mut atyp).await?;
        let mut addr = [0u8; 4];
        socket.read_exact(&mut addr).await?;
        let mut port = [0u8; 2];
        socket.read_exact(&mut port).await?;

        let mut metadata = ConnectionMetadata::new(Endpoint::new_ip(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr)),
            u16::from_be_bytes(port),
        ));
        metadata.identity.set_remote_peer_source(Endpoint::new_ip(
            "127.0.0.1".parse().expect("probe peer ip"),
            40_000,
        ));
        metadata.environment.inbound_tag = Some(self.tag.clone());

        self.engine
            .send_event(EngineEvent::NewStream {
                context: Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata))),
                stream: Box::new(socket),
            })
            .await?;
        Ok(())
    }
}

fn probe_spec() -> ProtocolSpec {
    ProtocolSpec {
        tag: PROBE,
        aliases: &["g4-probe-alias"],
        outbound: Some(OutboundSpec {
            validate: |raw, protocol| parse_probe(raw, protocol).map(|_| ()),
            build: |r: &OutboundRequest<'_>| {
                let s = parse_probe(r.settings, r.protocol)?;
                Ok(Arc::new(ProbeOutbound {
                    tag: r.tag.to_string(),
                    server: s.server,
                    port: s.port,
                }) as Arc<dyn OutboundDialer>)
            },
        }),
        inbound: Some(InboundSpec {
            default_listen: "127.0.0.1",
            default_port: 0,
            validate: Some(|raw, protocol| parse_probe(raw, protocol).map(|_| ())),
            build: |r: &InboundRequest<'_>| {
                // The inbound's own dial target is irrelevant — it relays — but
                // the settings must still parse strictly, which is the point.
                parse_probe(r.settings.unwrap_or(&serde_json::Value::Null), r.protocol)?;
                PROBE_INBOUND_BUILDS.fetch_add(1, Ordering::SeqCst);
                Ok(InboundPlan::Register(Arc::new(ProbeInbound {
                    tag: r.tag.to_string(),
                    listen_addr: r.listen_addr.clone(),
                    engine: r.engine.clone(),
                })))
            },
        }),
    }
}

/// The registry an integrator would build: everything the engine ships, plus
/// the protocol that ships nowhere. This single `with` is the whole of G4.
fn probe_registry() -> ProtocolRegistry {
    ProtocolRegistry::builtin().with(probe_spec())
}

/// A config whose only non-builtin entries are `g4-probe` — spelled by
/// canonical tag on the inbound and by *alias* on the outbound, so both
/// spellings are exercised.
fn probe_config(inbound_port: u16, upstream_port: u16) -> Config {
    let settings = || {
        serde_json::json!({
            "marker": "g4-probe-live",
            "server": "127.0.0.1",
            "port": upstream_port,
        })
    };
    Config {
        inbounds: vec![InboundConfig {
            tag: "probe-in".into(),
            protocol: PROBE.into(),
            listen: Some("127.0.0.1".into()),
            port: Some(inbound_port),
            settings: Some(settings()),
        }],
        outbounds: vec![OutboundConfig {
            tag: "probe-out".into(),
            protocol: "g4-probe-alias".into(),
            settings: Some(settings()),
        }],
        // Route to the probe outbound, not a builtin: if this fell through to
        // the dispatcher's legacy bypass the relay test below would fail,
        // because no `direct` outbound exists in this config at all.
        routing: RoutingConfig { rules: vec![], default_outbound: "probe-out".into() },
        dns: DnsConfig { servers: vec![], fake_ip: None, execution_model: None },
        api: None,
    }
}

/// A port the OS says is free. Racy in principle, free of collisions in
/// practice — and if it were ever taken, the test fails loudly on bind rather
/// than passing for the wrong reason.
async fn free_port() -> u16 {
    let listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe for a free port");
    let port = listener.local_addr().expect("free port addr").port();
    drop(listener);
    port
}

// ---------------------------------------------------------------------------
// The claim, end to end
// ---------------------------------------------------------------------------

/// **The G4 claim.** A protocol defined in this test file, registered through
/// one registry entry, relays live traffic through the whole engine —
/// validation, construction, inbound registration, routing and dial — with no
/// edit to `system.rs`, `dispatcher.rs`, `config/mod.rs`, or any `match`
/// anywhere in the engine.
///
/// This is the test RFC-012 G4 should have shipped with. Without it, "the
/// match chains are gone" and "adding a protocol needs no match edits" are two
/// different claims, and only the second is what G4 asserts.
///
/// The destination is TEST-NET-3 (RFC 5737), which passes the dispatcher's
/// relay guard and is guaranteed never to be a local interface, so nothing
/// here can pass by accidentally reaching a real service on this host.
#[tokio::test]
async fn a_protocol_added_at_runtime_dials_and_relays_traffic() {
    // The upstream the probe outbound will be asked to dial.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind echo server");
    let upstream_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.expect("echo accept");
        let mut buf = vec![0u8; 64];
        let n = socket.read(&mut buf).await.expect("echo read");
        let _ = socket.write_all(&buf[..n]).await;
    });

    // Preconditions, asserted rather than assumed. Without these a pass could
    // be explained by the engine accepting anything.
    assert!(
        ProtocolRegistry::builtin().get(PROBE).is_none(),
        "precondition: '{PROBE}' must not exist in the builtin table, or this test \
         proves nothing about extension"
    );
    assert!(
        probe_config(0, upstream_port).validate_strict().is_err(),
        "precondition: builtin validation must reject '{PROBE}'"
    );

    let inbound_port = free_port().await;
    let mut system = ShadowMeshSystem::new_with_protocols(
        probe_config(inbound_port, upstream_port),
        probe_registry(),
    )
    .await
    .expect("a protocol added only to the registry must compose");
    system.start().await.expect("starts");

    assert!(
        PROBE_INBOUND_BUILDS.load(Ordering::SeqCst) > 0,
        "the probe inbound's constructor must have run during composition — if it did \
         not, composing proves nothing about '{PROBE}'"
    );

    // Drive it: connect to the probe inbound and send the address header the
    // real dispatcher path expects, then the payload. The inbound binds on
    // `system.start()`, so give the accept a moment to be listening — the
    // bounded retry is what makes this robust against a loaded CI box without
    // making it flaky.
    let mut socket = {
        let mut last = None;
        let mut connected = None;
        for _ in 0..50 {
            match tokio::time::timeout(
                Duration::from_millis(200),
                tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)),
            )
            .await
            {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => last = Some(e.to_string()),
                Err(_) => last = Some("timed out".to_string()),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        connected.unwrap_or_else(|| {
            panic!("client could not reach the probe inbound on {inbound_port}: {last:?}")
        })
    };

    // TEST-NET-3 (RFC 5737): passes the relay guard, never a local interface,
    // so the destination cannot accidentally name a real service on this host.
    socket.write_all(&[1u8, 203, 0, 113, 7]).await.expect("write atyp + TEST-NET-3 ip");
    socket.write_all(&443u16.to_be_bytes()).await.expect("write port");
    socket.write_all(b"g4-relay-probe").await.expect("write payload");
    socket.flush().await.expect("flush");

    let mut reply = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut reply))
        .await
        .expect("the relay must complete, not hang")
        .expect("the relay must not error");
    assert_eq!(
        &reply, b"g4-relay-probe",
        "the probe protocol must relay bytes through the real dispatcher"
    );
    assert!(
        PROBE_OUTBOUND_DIALS.load(Ordering::SeqCst) > 0,
        "the probe's own dialer must have been the one used, not a builtin fallback"
    );

    system.shutdown().await.expect("shuts down");
}

/// **The negative control.** Every assertion above is worthless without it:
/// the same config through the *default* path must be refused, so the pass
/// above can only be explained by the registry entry.
///
/// This is the pair that makes the claim testable. Reverting
/// `probe_registry()` to `ProtocolRegistry::builtin()` turns the relay test
/// into a failure — which is the property under test.
#[tokio::test]
async fn without_the_registry_entry_the_engine_refuses_the_protocol() {
    let config = probe_config(0, 1);
    // Not `expect_err`: that needs `Debug` on the `Ok` type, and
    // `ShadowMeshSystem` holds sockets and an actor for no reason to be
    // printable. Matching on the error keeps the assertion just as strict
    // without inventing a `Debug` impl nobody asked for.
    let Err(err) = ShadowMeshSystem::new_with_protocols(config, ProtocolRegistry::builtin()).await
    else {
        panic!("the builtin table must refuse a protocol it has never heard of");
    };
    let text = format!("{err:#}");
    assert!(text.contains(PROBE), "the error must name the protocol: {text}");
}

/// Adding a protocol must not weaken strictness. A typo'd key on the newly
/// added protocol is still a hard config error — the property G4's typed
/// settings buy, checked through the engine rather than the parser.
#[tokio::test]
async fn an_added_protocol_keeps_strict_validation_through_the_engine() {
    let mut config = probe_config(0, 1);
    config.inbounds[0].settings =
        Some(serde_json::json!({ "markr": "typo", "server": "127.0.0.1", "port": 1 }));

    let Err(err) = ShadowMeshSystem::new_with_protocols(config, probe_registry()).await else {
        panic!("a typo'd key on a newly added protocol must be a hard error");
    };
    assert!(format!("{err:#}").contains("markr"), "the error must name the offending key: {err:#}");
}

// ---------------------------------------------------------------------------
// The structural guard
// ---------------------------------------------------------------------------

/// Files that used to carry a `match` chain keyed on `protocol.as_str()`, and
/// that must not again.
const DISPATCH_PATH: &[&str] = &[
    "src/engine/system.rs",
    "src/engine/dispatcher.rs",
    "src/config/mod.rs",
    "src/protocol_registry.rs",
];

/// Protocol-name string literals. A `match` arm keyed on one of these is the
/// old dispatch shape reappearing; the registry must be the only table.
const PROTOCOL_LITERALS: &[&str] = &[
    "\"socks\"",
    "\"http\"",
    "\"tun\"",
    "\"direct\"",
    "\"freedom\"",
    "\"shadowsocks\"",
    "\"trojan\"",
    "\"vless\"",
    "\"vmess\"",
    "\"wireguard\"",
    "\"hysteria\"",
    "\"tuic\"",
];

/// No protocol-name literal may appear as a `match` arm pattern in the
/// dispatch path.
///
/// The pattern is deliberately narrow — a literal immediately followed by `=>`
/// — so it cannot fire on a protocol name mentioned in a comment, in a string
/// comparison, in a struct literal (`ProtocolSpec { tag: "tuic", .. }`), or in a
/// test fixture. `System`'s own `match stage { Stage::Start => .. }` is
/// unaffected because `"race"` is not in the list and `Stage::Start` is not a
/// literal.
///
/// This is the half of the proof that behaviour cannot supply. The relay test
/// shows the registry works; this shows nothing is quietly matching behind it —
/// which is exactly the regression G4 exists to prevent: four lists that must
/// agree, silently drifting apart. The drift was not hypothetical — `tuic` was
/// present in both constructors and absent from validation, making it
/// unreachable.
#[test]
fn the_dispatch_path_contains_no_protocol_match() {
    let crate_root = env!("CARGO_MANIFEST_DIR");
    let mut offenders = Vec::new();

    for rel in DISPATCH_PATH {
        let path = std::path::Path::new(crate_root).join(rel);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for literal in PROTOCOL_LITERALS {
                let rest = &trimmed[literal.len().min(trimmed.len())..];
                if trimmed.starts_with(literal) && rest.trim_start().starts_with("=>") {
                    offenders.push(format!("{}:{}: {}", rel, idx + 1, trimmed));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "protocol dispatch must be registry iteration, not a match chain. These arms \
         reintroduce the parallel lists RFC-012 G4 removed:\n{}",
        offenders.join("\n")
    );
}
