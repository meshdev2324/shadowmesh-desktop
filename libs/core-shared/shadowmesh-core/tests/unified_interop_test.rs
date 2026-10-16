//! Unified interop: this project's **real** VLESS inbound against this
//! project's **real** VLESS outbound.
//!
//! # Why this file exists
//!
//! It used to contain a single test with **zero assertions** whose body ended
//! mid-sentence ("Wait, let's use the real VlessInbound::listen logic but we
//! need the port"). It fired ~40 lines of code, discarded every result, and
//! could not fail on anything.
//!
//! The gap it was groping at is real and was still open:
//! `vless_integration_test.rs` exercises `VlessOutbound` against a
//! **hand-rolled mock server**, so nothing tested `VlessInbound::listen()` —
//! the inbound that actually faces the internet — end to end. Both halves of
//! the protocol live in this crate and drifting apart is exactly the class of
//! bug a unified test exists to catch, and it is invisible from the far side
//! of a mock.
//!
//! So the test is completed here rather than deleted. The "we need the port"
//! problem is solved by binding a listener, recording its port, dropping it,
//! and retrying the dial until `listen()` has won the bind; the retry is what
//! makes it a test rather than a coin flip.
//!
//! Everything is loopback. The decoy path is exercised against a local
//! listener, never against the real `www.google.com` default.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use shadowmesh_core::engine::actor::EngineHandle;
use shadowmesh_core::engine::context::{ConnectionContext, SharedContext};
use shadowmesh_core::engine::events::EngineEvent;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::transport::inbound::vmess::VlessInbound;
use shadowmesh_core::transport::outbound::vmess::VlessOutbound;
use shadowmesh_core::transport::traits::{AsyncIoStream, InboundListener, OutboundDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// The payload the round trip has to preserve byte-for-byte. It is longer than
/// one loopback segment, so a stream that dropped or reordered its tail cannot
/// pass, and it mixes NUL/high bytes so a text-mode slip cannot hide either.
const PAYLOAD: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// What the decoy answers with. Distinct from anything the echo server sends,
/// so "the decoy answered" cannot be confused with "the real path ran".
const DECOY_REPLY: &[u8] = b"DECOY";

/// How long to keep retrying while `listen()` wins the bind race.
const LISTEN_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// A loopback listener that echoes everything back, plus its address.
async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, handle)
}

/// Reserves a loopback port for an inbound that will bind it itself.
///
/// `VlessInbound::listen()` takes an address, not a listener, so the port has
/// to be chosen before it binds. Retrying the dial closes that race; sleeping a
/// hopeful amount would only make it a flake.
async fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// Retries `connect` until the inbound has bound its reserved port.
async fn connect_when_ready(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + LISTEN_READY_TIMEOUT;
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the VLESS inbound never started listening within {LISTEN_READY_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Retries the real outbound's dial until the inbound is listening.
async fn dial_when_ready(
    outbound: &VlessOutbound,
    destination: Endpoint,
) -> Box<dyn AsyncIoStream> {
    let deadline = tokio::time::Instant::now() + LISTEN_READY_TIMEOUT;
    loop {
        let context: SharedContext = Arc::new(Mutex::new(ConnectionContext::new(
            ConnectionMetadata::new(destination.clone()),
        )));
        if let Ok(stream) = outbound.dial_stream(context).await {
            return stream;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "could not complete a VLESS handshake within {LISTEN_READY_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Builds a VLESS request header by hand, in the wire order
/// `parse_vless_handshake` expects: version, UUID, addons length, command,
/// port, address type, address.
///
/// Hand-built on purpose for the negative test: the real outbound refuses to
/// return a stream when the server's reply is not a VLESS success byte, so it
/// cannot be used to observe what the inbound does with a *wrong* UUID.
fn vless_request_header(uuid: &Uuid, dest: &Endpoint) -> Vec<u8> {
    let mut h = vec![0x00];
    h.extend_from_slice(uuid.as_bytes());
    h.push(0x00); // addons length
    h.push(0x01); // cmd = TCP connect
    h.extend_from_slice(&dest.port.to_be_bytes());
    match &dest.addr {
        shadowmesh_core::engine::metadata::Addr::Ip(std::net::IpAddr::V4(ip)) => {
            h.push(0x01);
            h.extend_from_slice(&ip.octets());
        }
        shadowmesh_core::engine::metadata::Addr::Ip(std::net::IpAddr::V6(ip)) => {
            h.push(0x04);
            h.extend_from_slice(&ip.octets());
        }
        shadowmesh_core::engine::metadata::Addr::Domain(d) => {
            h.push(0x03);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        }
    }
    h
}

/// A full client -> inbound -> engine -> destination round trip.
///
/// Every assertion is load-bearing. Without the `[0, 0]` success byte from
/// `handle_established` the outbound never hands back a stream; without the
/// engine forwarding, the echo never arrives; without byte equality, a stream
/// that silently dropped or reordered its tail would still pass. The recorded
/// destination is what proves the *inbound* decoded the header, rather than
/// the round trip succeeding for some other reason.
#[tokio::test]
async fn vless_outbound_and_inbound_interoperate_end_to_end() {
    let _ = tracing_subscriber::fmt::try_init();

    let (echo_addr, _echo) = spawn_echo_server().await;
    let (engine, mut destinations) = spawn_engine_forwarder();

    let uuid_str = Uuid::new_v4().to_string();
    let port = reserve_port().await;

    let inbound = VlessInbound::new(
        "server-in".into(),
        format!("127.0.0.1:{port}"),
        &uuid_str,
        engine,
        None,
        None,
    )
    .unwrap();
    tokio::spawn(async move { inbound.listen().await });

    let outbound = VlessOutbound::new(
        "client-out".into(),
        "127.0.0.1".into(),
        port,
        &uuid_str,
        "".into(),
        None,
    )
    .unwrap();

    // The outbound cannot connect the destination itself; it *names* it in the
    // request, and the engine is what actually dials.
    let destination = Endpoint::new_ip(echo_addr.ip(), echo_addr.port());
    let mut stream = dial_when_ready(&outbound, destination).await;

    stream.write_all(PAYLOAD).await.unwrap();
    let mut echoed = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("the echo server never answered")
        .expect("the stream closed before the payload came back");
    assert_eq!(&echoed, PAYLOAD, "the payload did not survive the round trip");

    drop(stream);
    let seen = tokio::time::timeout(Duration::from_secs(5), destinations.recv())
        .await
        .expect("the engine never received a NewStream")
        .expect("the forwarder task panicked");
    assert_eq!(
        seen,
        echo_addr.to_string(),
        "the inbound must forward exactly the destination the client asked for"
    );
    assert!(
        destinations.try_recv().is_err(),
        "one handshake must produce exactly one engine stream"
    );
}

/// Forwards every `NewStream` the engine receives to its real destination, and
/// reports each destination over an unbounded channel.
///
/// A channel rather than a completion signal because `VlessInbound::listen()`
/// never returns: it holds an `EngineHandle`, so the receiver stays open for
/// the life of the test and the forwarder can only be observed, not joined.
fn spawn_engine_forwarder() -> (EngineHandle, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let (tx, rx) = async_channel::unbounded();
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let EngineEvent::NewStream { context, mut stream } = event {
                let host = context.lock().metadata.identity.destination.to_string();
                let _ = seen_tx.send(host.clone());
                if let Ok(mut target) = TcpStream::connect(&host).await {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                }
            }
        }
    });
    (EngineHandle::new(tx), seen_rx)
}

/// A decoy that answers every connection with [`DECOY_REPLY`] and counts hits.
async fn spawn_decoy() -> (std::net::SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = socket.write_all(DECOY_REPLY).await;
                // Hold the connection open long enough for the caller to read.
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    (addr, hits, handle)
}

/// A client presenting the wrong UUID must be decoyed and must never reach the
/// engine.
///
/// This is the authorization half of interop: a unified test that only ever
/// dialled with the correct UUID would pass even if `uuid_eq` were deleted
/// outright. The decoy points at a loopback listener, so this stays offline.
///
/// The test also dials with the *correct* UUID on the same inbound afterwards.
/// Without that, "the engine saw nothing" would be satisfied just as well by an
/// engine that never sees anything — the assertion would be vacuous in exactly
/// the way this file originally was.
#[tokio::test]
async fn a_wrong_uuid_is_decoyed_and_never_reaches_the_engine() {
    let _ = tracing_subscriber::fmt::try_init();

    let (event_tx, event_rx) = async_channel::unbounded();
    let engine = EngineHandle::new(event_tx);

    let correct = Uuid::new_v4();
    let port = reserve_port().await;
    let (decoy_addr, decoy_hits, _decoy) = spawn_decoy().await;

    let inbound = VlessInbound::new(
        "server-in".into(),
        format!("127.0.0.1:{port}"),
        &correct.to_string(),
        engine,
        None,
        Some(decoy_addr.to_string()),
    )
    .unwrap();
    tokio::spawn(async move { inbound.listen().await });

    // The destination is irrelevant here — a wrong UUID must be rejected before
    // anything is dialled — so it points at a closed loopback port.
    let destination = Endpoint::new_ip("127.0.0.1".parse().unwrap(), 1);

    // --- wrong UUID: decoyed, and the engine sees nothing ------------------
    let mut impostor = connect_when_ready(port).await;
    impostor.write_all(&vless_request_header(&Uuid::new_v4(), &destination)).await.unwrap();

    let mut reply = [0u8; DECOY_REPLY.len()];
    tokio::time::timeout(Duration::from_secs(10), impostor.read_exact(&mut reply))
        .await
        .expect("the decoy never answered a wrong-UUID handshake")
        .expect("the connection closed before the decoy answered");
    assert_eq!(&reply, DECOY_REPLY, "a wrong UUID must be proxied to the decoy");
    assert_eq!(
        decoy_hits.load(Ordering::SeqCst),
        1,
        "the wrong-UUID connection must reach the decoy exactly once"
    );
    assert!(event_rx.try_recv().is_err(), "a handshake with a wrong UUID reached the engine");

    // --- correct UUID on the same listener: the engine DOES see it --------
    // This is the anti-vacuity control. Without it the assertion above could
    // not tell "correctly rejected" apart from "the engine channel is broken".
    let mut genuine = connect_when_ready(port).await;
    genuine.write_all(&vless_request_header(&correct, &destination)).await.unwrap();

    let mut ack = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), genuine.read_exact(&mut ack))
        .await
        .expect("the correct UUID was not acknowledged")
        .expect("the connection closed before the success byte");
    assert_eq!(ack, [0x00, 0x00], "a correct UUID must get the VLESS success response");

    match tokio::time::timeout(Duration::from_secs(5), event_rx.recv()).await {
        Ok(Ok(EngineEvent::NewStream { .. })) => {}
        _ => panic!("the correct-UUID handshake did not reach the engine"),
    }
}
