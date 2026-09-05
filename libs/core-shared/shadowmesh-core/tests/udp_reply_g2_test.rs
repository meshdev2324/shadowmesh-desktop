//! RFC-012 G2 end-to-end UDP reply tests.
//!
//! Scenario: a UDP client sends a query through a Shadowsocks inbound to an
//! upstream UDP echo server, and expects the reply to come back encrypted.
//! This pins the full reply chain: inbound → EngineEvent (reply channel) →
//! dispatcher → outbound (send_packet with reply) → actor oneshot → inbound
//! re-encryption → client.
//!
//! Implementation Source:
//! - Specification: Shadowsocks AEAD (SIP007) UDP packet format; RFC-012 G2.
//! - Security considerations: replies are bounded (2.5s) so a stalled
//!   upstream cannot wedge the listener loop. The test key is provided via
//!   an environment variable (never a hardcoded literal).

use shadowmesh_core::engine::actor::{EngineActor, EngineHandle};
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::dispatcher::Dispatcher;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use shadowmesh_core::engine::registry::ConnectionRegistry;
use shadowmesh_core::protocol::shadowsocks::{ShadowsocksCipher, ShadowsocksMethod};
use shadowmesh_core::router::engine::RoutingPipeline;
use shadowmesh_core::transport::inbound::shadowsocks::{parse_ss_address, ShadowsocksInbound};
use shadowmesh_core::transport::outbound::direct::DirectOutbound;
use shadowmesh_core::transport::outbound::registry::OutboundRegistry;
use shadowmesh_core::transport::traits::{InboundListener, OutboundDialer};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Ephemeral test key sourced from the environment (CI exports a random one).
/// Fallback is a random UUID: unique per run, never persisted.
fn test_password() -> String {
    std::env::var("SM_TEST_UDP_PASSWORD").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
}

/// Spawns a UDP echo server on an ephemeral port.
async fn spawn_udp_echo() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv");
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_ss_udp_full_roundtrip_with_reply() {
    // 1. Upstream echo.
    let echo_addr = spawn_udp_echo().await;
    let password = test_password();

    // 2. Engine wiring: registry + pipeline (default → direct) + dispatcher.
    let registry = Arc::new(ConnectionRegistry::new());
    let pipeline = Arc::new(RoutingPipeline::new(vec![]));
    let outbounds = Arc::new(OutboundRegistry::new());
    let direct = Arc::new(DirectOutbound::new("direct".to_string()));
    outbounds.register(direct).await;

    let dns_router = Arc::new(shadowmesh_core::dns::DnsRouter::new(
        vec![],
        shadowmesh_core::dns::ExecutionModel::Serial,
    ));
    let dispatcher = Arc::new(Dispatcher::new(registry, pipeline, dns_router, outbounds));

    let (tx, rx) = async_channel::unbounded();
    let engine_handle = EngineHandle::new(tx);
    let actor = EngineActor::new(rx, dispatcher);
    tokio::spawn(async move {
        let _ = actor.run().await;
    });

    // 3. SS inbound on an ephemeral UDP port.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inbound_addr = probe.local_addr().unwrap();
    drop(probe);
    let inbound = ShadowsocksInbound::new(
        "ss-in".to_string(),
        inbound_addr.to_string(),
        "aes-256-gcm".to_string(),
        password.clone(),
        engine_handle,
    )
    .expect("inbound");
    tokio::spawn(async move {
        let _ = inbound.listen().await;
    });
    // Wait for the inbound's UDP socket to bind.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 4. Client: build a SIP007 request toward the echo server.
    let dest = Endpoint::new_ip(echo_addr.ip(), echo_addr.port());
    let method = ShadowsocksMethod::Aes256Gcm;

    let mut request = Vec::new();
    match &dest.addr {
        shadowmesh_core::engine::metadata::Addr::Ip(std::net::IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        _ => unreachable!("test uses v4"),
    }
    request.extend_from_slice(&dest.port.to_be_bytes());
    request.extend_from_slice(b"HELLO-DNS");

    let encrypted_request =
        ShadowsocksCipher::encrypt_udp(method, &password, &request).expect("encrypt");

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&encrypted_request, inbound_addr).await.unwrap();

    // 5. Receive the encrypted reply and verify the payload round-tripped.
    let mut rbuf = [0u8; 65535];
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (n, _) = client.recv_from(&mut rbuf).await.expect("client recv");
            if let Ok(plain) = ShadowsocksCipher::decrypt_udp(method, &password, &rbuf[..n]) {
                if let Ok((payload, ep)) = parse_ss_address(&plain) {
                    return (payload.to_vec(), ep);
                }
            }
        }
    })
    .await
    .expect("reply arrived within 5s");

    assert_eq!(reply.0, b"HELLO-DNS");
    assert_eq!(reply.1.port, echo_addr.port());
}

/// The direct outbound's reply path in isolation: send → recv_from bound.
#[tokio::test]
async fn test_direct_udp_send_packet_returns_reply() {
    let echo_addr = spawn_udp_echo().await;
    let outbound = DirectOutbound::new("direct".to_string());

    let dest = Endpoint::new_ip(echo_addr.ip(), echo_addr.port());
    let mut metadata = ConnectionMetadata::new(dest);
    metadata.l4_protocol = L4Protocol::Udp;
    let context: shadowmesh_core::engine::context::SharedContext =
        Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)));

    let reply = outbound
        .send_packet(context, b"PING", "127.0.0.1:53530".parse().unwrap())
        .await
        .expect("send+reply");

    assert_eq!(reply, b"PING");
}
