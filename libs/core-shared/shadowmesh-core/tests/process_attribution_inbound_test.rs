//! Inbound transports must never let a remote peer be attributed to a local
//! process.
//!
//! # What these tests are for
//!
//! `Dispatcher::enrich_metadata` used to fill `metadata.identity.process_name`
//! by resolving `identity.source.port` against this host's `/proc/net/tcp{,6}`.
//! On an inbound connection `identity.source` is the *remote peer's* endpoint,
//! so a peer's ephemeral source port was matched against whatever unrelated
//! local listener sat on the same number, and the inbound packet was labelled
//! with that listener's process name. `Condition::ProcessName` matches on that
//! name, so it chose a route and a shaping profile.
//!
//! The dispatcher-level policy is covered in `dispatcher::tests`. What is
//! covered *here* is the half only the transports can satisfy: each one must
//! state, before dispatch, that its source is a remote peer. So every test
//! below drives a real listener through a real client handshake and inspects
//! the `ConnectionContext` the transport actually handed to the engine -- not
//! a metadata object the test assembled itself.
//!
//! # Why the tests would have been red before the fix
//!
//! The client in each test is a TCP socket *owned by this very test process*,
//! on an ephemeral port. Every test asserts that first: the colliding local
//! socket exists and resolves to this pid. A test that could not prove its own
//! collision would pass whether or not the bug was fixed.

use shadowmesh_core::engine::events::EngineEvent;
use shadowmesh_core::engine::metadata::{Addr, ConnectionMetadata, Endpoint, SourceOrigin};
use shadowmesh_core::engine::process::{attribute_process_identity, ProcessSearcher};
use shadowmesh_core::engine::EngineHandle;
use shadowmesh_core::protocol::shadowsocks::{PaddingMode, ShadowsocksMethod, ShadowsocksStream};
use shadowmesh_core::router::rule::Condition;
use shadowmesh_core::transport::inbound::http::HttpInbound;
use shadowmesh_core::transport::inbound::shadowsocks::ShadowsocksInbound;
use shadowmesh_core::transport::inbound::socks::SocksInbound;
use shadowmesh_core::transport::inbound::trojan::TrojanInbound;
use shadowmesh_core::transport::inbound::vmess::VlessInbound;
use shadowmesh_core::transport::traits::InboundListener;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

/// Anything slower than this means the handshake never reached dispatch, which
/// is a failure of the test setup rather than a slow machine.
const DISPATCH_DEADLINE: Duration = Duration::from_secs(10);

/// A destination that is not node-local, so nothing about this test depends on
/// the dispatcher's SSRF guard.
fn destination() -> Endpoint {
    Endpoint::new_ip("198.51.100.9".parse().expect("test destination ip"), 80)
}

/// A free loopback port, released before the inbound binds it.
async fn free_loopback_addr() -> SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    probe.local_addr().expect("probe addr")
}

type EventRx = async_channel::Receiver<EngineEvent>;

/// Connect once the inbound is listening.
///
/// `InboundListener::listen` binds inside the spawned task, so the port is
/// briefly closed between the spawn and the bind. Retrying is the honest way to
/// synchronise on that without reaching into the listener for a readiness
/// signal the trait does not expose.
async fn connect_when_listening(addr: SocketAddr) -> tokio::net::TcpStream {
    let deadline = tokio::time::Instant::now() + DISPATCH_DEADLINE;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("could not connect to the inbound at {addr}: {e}"),
        }
    }
}

/// A private engine channel plus a handle to hand to an inbound. No actor runs
/// on it, so the test receives exactly the event the transport emitted.
fn engine_channel() -> (EngineHandle, EventRx) {
    let (tx, rx) = async_channel::unbounded();
    (EngineHandle::new(tx), rx)
}

/// The metadata the transport handed to the engine.
async fn dispatched_metadata(rx: &EventRx, transport: &str) -> ConnectionMetadata {
    let event = tokio::time::timeout(DISPATCH_DEADLINE, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{transport} never dispatched within {DISPATCH_DEADLINE:?}"))
        .unwrap_or_else(|_| panic!("{transport} engine channel closed before dispatch"));

    match event {
        EngineEvent::NewStream { context, .. } | EngineEvent::UdpPacket { context, .. } => {
            context.lock().metadata.clone()
        }
        _ => panic!("{transport} dispatched an event that carries no connection context"),
    }
}

/// The assertion every inbound transport has to satisfy.
///
/// `metadata` is what the transport built; `transport` names it in failures.
async fn assert_peer_never_attributed(metadata: &ConnectionMetadata, transport: &str) {
    assert_eq!(
        metadata.identity.source_origin,
        Some(SourceOrigin::RemotePeer),
        "{transport}: identity.source_origin must say the source is a remote peer, \
         got {:?}. An unstated origin reads as a peer too, so a transport that \
         silently stopped setting a source is caught by the next assertion.",
        metadata.identity.source_origin
    );

    let source = metadata
        .identity
        .source
        .as_ref()
        .unwrap_or_else(|| panic!("{transport}: no source endpoint recorded"));
    let peer_port = source.port;

    // The precondition. The client socket is a TCP socket owned by this test
    // process on that same port, so a port-only lookup finds it -- which is
    // exactly the collision the defect turned into a wrong process name.
    let colliding = ProcessSearcher::find_process_info(peer_port).await.unwrap_or_else(|| {
        panic!(
            "{transport}: peer port {peer_port} does not resolve to any local process, \
             so this test cannot demonstrate the collision and proves nothing"
        )
    });
    assert_eq!(
        colliding.pid,
        std::process::id(),
        "{transport}: expected the colliding port {peer_port} to belong to this \
         test process, got {colliding:?}"
    );

    let mut identity = metadata.identity.clone();
    let outcome = attribute_process_identity(&mut identity).await;

    assert!(outcome.is_remote_peer(), "{transport}: got outcome {outcome:?}");
    assert_eq!(
        identity.process_name, None,
        "{transport}: inbound peer was attributed to {:?}, which only owns \
         port {peer_port} locally",
        identity.process_name
    );

    // The routing consequence, stated directly: the process that happens to
    // own the colliding port must not match a rule on this connection.
    assert!(
        !Condition::ProcessName(colliding.name).matches(metadata),
        "{transport}: a ProcessName rule for the colliding local process \
         matched an inbound peer connection"
    );
}

// --- Shadowsocks (TCP) -----------------------------------------------------

#[tokio::test]
async fn shadowsocks_inbound_marks_its_peer_as_remote() {
    let listen_addr = free_loopback_addr().await;
    let (engine, rx) = engine_channel();
    // Ephemeral random key material; no credential-shaped literal. One value,
    // shared by the listener and the client -- a mismatch here fails as
    // "never dispatched", which is a confusing way to learn about it.
    let password = uuid::Uuid::new_v4().to_string();
    let method = ShadowsocksMethod::Aes256Gcm;
    let inbound = ShadowsocksInbound::new(
        "ss-in".to_string(),
        listen_addr.to_string(),
        "aes-256-gcm".to_string(),
        password.clone(),
        engine,
    )
    .expect("build shadowsocks inbound");

    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });

    let raw = connect_when_listening(listen_addr).await;
    let mut ss = ShadowsocksStream::with_options(raw, method, &password, PaddingMode::Off);

    use tokio::io::AsyncWriteExt;
    let dest = destination();
    let mut frame = vec![0x01];
    match dest.addr {
        Addr::Ip(std::net::IpAddr::V4(v4)) => {
            frame.extend_from_slice(&v4.octets());
        }
        _ => panic!("test destination must be IPv4"),
    }
    frame.extend_from_slice(&dest.port.to_be_bytes());
    frame.extend_from_slice(b"GET / HTTP/1.0\r\n\r\n");
    ss.write_all(&frame).await.expect("write ss target address");

    let metadata = dispatched_metadata(&rx, "shadowsocks").await;
    assert_eq!(metadata.environment.inbound_tag.as_deref(), Some("ss-in"));
    await_and_assert(&metadata, "shadowsocks").await;
}

// --- SOCKS5 ----------------------------------------------------------------

#[tokio::test]
async fn socks_inbound_marks_its_peer_as_remote() {
    let listen_addr = free_loopback_addr().await;
    let (engine, rx) = engine_channel();
    let inbound = SocksInbound::new("socks-in".to_string(), listen_addr.to_string(), engine);

    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = connect_when_listening(listen_addr).await;

    // RFC 1928 greeting, then a CONNECT request for an IPv4 destination.
    stream.write_all(&[0x05, 0x01, 0x00]).await.expect("write greeting");
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.expect("read method selection");
    assert_eq!(&greeting, &[0x05, 0x00], "server must select no-auth");

    let dest = destination();
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match dest.addr {
        Addr::Ip(std::net::IpAddr::V4(v4)) => {
            request.extend_from_slice(&v4.octets());
        }
        _ => panic!("test destination must be IPv4"),
    }
    request.extend_from_slice(&dest.port.to_be_bytes());
    stream.write_all(&request).await.expect("write socks request");

    let metadata = dispatched_metadata(&rx, "socks").await;
    assert_eq!(metadata.environment.inbound_tag.as_deref(), Some("socks-in"));
    await_and_assert(&metadata, "socks").await;
}

// --- HTTP CONNECT ----------------------------------------------------------

#[tokio::test]
async fn http_inbound_marks_its_peer_as_remote() {
    let listen_addr = free_loopback_addr().await;
    let (engine, rx) = engine_channel();
    let inbound = HttpInbound::new("http-in".to_string(), listen_addr.to_string(), engine);

    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });

    use tokio::io::AsyncWriteExt;
    let mut stream = connect_when_listening(listen_addr).await;
    stream
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        .await
        .expect("write CONNECT request");

    let metadata = dispatched_metadata(&rx, "http").await;
    assert_eq!(metadata.environment.inbound_tag.as_deref(), Some("http-in"));
    await_and_assert(&metadata, "http").await;
}

// --- Trojan ----------------------------------------------------------------

#[tokio::test]
async fn trojan_inbound_marks_its_peer_as_remote() {
    use sha2::{Digest, Sha224};

    let listen_addr = free_loopback_addr().await;
    let (engine, rx) = engine_channel();
    let password = uuid::Uuid::new_v4().to_string();
    let digest = hex::encode(Sha224::digest(password.as_bytes()));
    let inbound =
        TrojanInbound::new("trojan-in".to_string(), listen_addr.to_string(), &password, engine);

    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });

    use tokio::io::AsyncWriteExt;
    let mut stream = connect_when_listening(listen_addr).await;
    let dest = destination();
    let mut frame = Vec::new();
    frame.extend_from_slice(digest.as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.push(0x01); // CMD: connect
    frame.push(0x01); // ATYP: IPv4
    match dest.addr {
        Addr::Ip(std::net::IpAddr::V4(v4)) => {
            frame.extend_from_slice(&v4.octets());
        }
        _ => panic!("test destination must be IPv4"),
    }
    frame.extend_from_slice(&dest.port.to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    stream.write_all(&frame).await.expect("write trojan header");

    let metadata = dispatched_metadata(&rx, "trojan").await;
    assert_eq!(metadata.environment.inbound_tag.as_deref(), Some("trojan-in"));
    await_and_assert(&metadata, "trojan").await;
}

// --- VLESS -----------------------------------------------------------------

#[tokio::test]
async fn vless_inbound_marks_its_peer_as_remote() {
    let listen_addr = free_loopback_addr().await;
    let (engine, rx) = engine_channel();
    let uuid = uuid::Uuid::new_v4();
    let inbound = VlessInbound::new(
        "vless-in".to_string(),
        listen_addr.to_string(),
        &uuid.to_string(),
        engine,
        None,
        None,
    )
    .expect("build vless inbound");

    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });

    use tokio::io::AsyncWriteExt;
    let mut stream = connect_when_listening(listen_addr).await;
    let dest = destination();
    let mut frame = Vec::new();
    frame.push(0x00); // version
    frame.extend_from_slice(uuid.as_bytes());
    frame.push(0x00); // addons length
    frame.push(0x01); // CMD: connect
    frame.extend_from_slice(&dest.port.to_be_bytes());
    frame.push(0x01); // ATYP: IPv4
    match dest.addr {
        Addr::Ip(std::net::IpAddr::V4(v4)) => {
            frame.extend_from_slice(&v4.octets());
        }
        _ => panic!("test destination must be IPv4"),
    }
    frame.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    stream.write_all(&frame).await.expect("write vless request");

    let metadata = dispatched_metadata(&rx, "vless").await;
    assert_eq!(metadata.environment.inbound_tag.as_deref(), Some("vless-in"));
    await_and_assert(&metadata, "vless").await;
}

/// Shared tail of every transport test. Named so the failure reads as
/// "this transport attributed a peer" rather than a bare assert.
async fn await_and_assert(metadata: &ConnectionMetadata, transport: &str) {
    assert_peer_never_attributed(metadata, transport).await;
}

// --- Cross-transport guard -------------------------------------------------

/// Every file under `src/transport` that records a source endpoint must go
/// through one of the two setters, and must say which side's socket it is.
///
/// This is the Rust-side stand-in for the shell metatests in `shell-ci.yml`.
/// The behavioural tests above cannot reach every transport -- Hysteria needs
/// a QUIC session, TUN needs a tun device, TUIC needs a real connection --
/// and a transport added tomorrow would arrive with no behavioural test at
/// all. What every transport has in common is that it is a file in this
/// directory, so the invariant can be checked for all of them at once.
///
/// The scan deliberately looks for the *raw* assignment `identity.source =`
/// rather than for the absence of a source: a transport that sets no source
/// records `NoSource`, which is safe, and should not have to be special-cased.
#[test]
fn every_transport_states_the_origin_of_the_source_it_records() {
    let transport_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transport");
    assert!(transport_root.is_dir(), "expected {} to exist", transport_root.display());

    // Transports that record a source, and the setter they must be using.
    let expected: [(&str, &str); 7] = [
        ("inbound/shadowsocks.rs", "set_remote_peer_source"),
        ("inbound/socks.rs", "set_remote_peer_source"),
        ("inbound/http.rs", "set_remote_peer_source"),
        ("inbound/vmess.rs", "set_remote_peer_source"),
        ("inbound/trojan.rs", "set_remote_peer_source"),
        ("hysteria.rs", "set_remote_peer_source"),
        ("inbound/tun.rs", "set_local_source"),
    ];

    let mut files = Vec::new();
    collect_rust_files(&transport_root, &mut files);
    assert!(!files.is_empty(), "found no .rs files under {}", transport_root.display());

    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let relative =
            path.strip_prefix(&transport_root).expect("under root").display().to_string();

        for (number, line) in text.lines().enumerate() {
            // Raw assignment: the origin is not stated, so it reads as a
            // remote peer and a locally-originated packet loses its name.
            assert!(
                !line.contains("identity.source =") && !line.contains("identity.source="),
                "{relative}:{} assigns identity.source directly ({}).\n\
                 Use Identity::set_local_source or Identity::set_remote_peer_source so \
                 the origin travels with the endpoint.",
                number + 1,
                line.trim()
            );
        }
    }

    for (relative, setter) in expected {
        let path = transport_root.join(relative);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(setter),
            "{relative} no longer calls {setter}. If this transport stopped \
             recording a source entirely that is safe (it becomes NoSource), \
             but if it still records one it must say whose socket it is."
        );
    }
}

fn collect_rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
