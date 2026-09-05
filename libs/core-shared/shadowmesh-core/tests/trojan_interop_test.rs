//! Trojan outbound wire-format interop tests.
//!
//! Implementation Source:
//! - Specification: Trojan Protocol (Public Documentation)
//! - Relevant sections: request header layout, CMD semantics (1 CONNECT,
//!   3 UDP ASSOCIATE), UDP packet framing.
//! - Security considerations: constant-time auth on the inbound side is
//!   tested separately; these tests pin the OUTBOUND wire bytes exactly.
//!
//! A mock Trojan server accepts the connection and asserts the header byte
//! layout, so any wire drift fails loudly before interop with real servers.

use sha2::{Digest, Sha224};
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use shadowmesh_core::transport::outbound::trojan::TrojanOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn context_for(
    destination: Endpoint,
    l4: L4Protocol,
) -> Arc<parking_lot::Mutex<ConnectionContext>> {
    let mut metadata = ConnectionMetadata::new(destination);
    metadata.l4_protocol = l4;
    Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)))
}

#[tokio::test]
async fn test_trojan_tcp_connect_header_wire_format() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        // [56 hex][CRLF][cmd=1][atyp=1][4 ip][2 port][CRLF][payload...]
        let mut head = vec![0u8; 56 + 2 + 1 + 1 + 4 + 2 + 2];
        sock.read_exact(&mut head).await.expect("read header");

        let expected_hash = {
            let mut h = Sha224::new();
            h.update(b"interpass");
            hex::encode(h.finalize())
        };
        assert_eq!(&head[..56], expected_hash.as_bytes());
        assert_eq!(&head[56..58], b"\r\n");
        assert_eq!(head[58], 0x01); // CMD CONNECT
        assert_eq!(head[59], 0x01); // ATYP IPv4
        assert_eq!(&head[60..64], &[127, 0, 0, 1]);
        assert_eq!(&head[64..66], &80u16.to_be_bytes());
        assert_eq!(&head[66..68], b"\r\n");

        // Echo the trailing payload back (simulates CONNECTed server data).
        let mut buf = [0u8; 64];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        if n > 0 {
            let _ = sock.write_all(&buf[..n]).await;
        }
    });

    let outbound =
        TrojanOutbound::new("trojan-test".into(), "127.0.0.1".into(), addr.port(), "interpass");

    let dest = Endpoint::new_ip("127.0.0.1".parse().unwrap(), 80);
    let ctx = context_for(dest, L4Protocol::Tcp);
    let mut stream = outbound.dial_stream(ctx).await.expect("dial");

    stream.write_all(b"ping").await.expect("write payload");
    stream.flush().await.expect("flush");

    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).await.expect("read echo");
    assert_eq!(&echo, b"ping");
    server.await.expect("server task");
}

#[tokio::test]
async fn test_trojan_udp_associate_framing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        // Handshake: [56 hex][CRLF][cmd=3][atyp=3][len][domain][port][CRLF]
        let mut head = vec![0u8; 56 + 2 + 1 + 1 + 1 + b"dns.example".len() + 2 + 2];
        sock.read_exact(&mut head).await.expect("read handshake");
        assert_eq!(head[58], 0x03); // CMD UDP ASSOCIATE
        assert_eq!(head[59], 0x03); // ATYP domain
        let dlen = head[60] as usize;
        assert_eq!(&head[61..61 + dlen], b"dns.example");

        // UDP frame: [atyp=3][len][domain][2 port][u16 len][payload]
        // The per-packet frame carries the true destination; the UDP
        // ASSOCIATE handshake above carried the same address per our client
        // policy (single-destination sessions keyed by context).
        let mut frame = vec![0u8; 1 + 1 + b"dns.example".len() + 2 + 2 + 12];
        sock.read_exact(&mut frame).await.expect("read frame");
        assert_eq!(frame[0], 0x03); // ATYP domain
        let dlen = frame[1] as usize;
        assert_eq!(&frame[2..2 + dlen], b"dns.example");
        assert_eq!(&frame[2 + dlen..4 + dlen], &53u16.to_be_bytes());
        assert_eq!(&frame[4 + dlen..6 + dlen], &12u16.to_be_bytes());
        assert_eq!(&frame[6 + dlen..18 + dlen], b"DNS-QUERY!!\0");
    });

    let outbound =
        TrojanOutbound::new("trojan-udp-test".into(), "127.0.0.1".into(), addr.port(), "interpass");

    let dest = Endpoint::new_domain("dns.example".into(), 53);
    let ctx = context_for(dest.clone(), L4Protocol::Udp);

    outbound
        .send_packet(ctx, b"DNS-QUERY!!\0", "127.0.0.1:53530".parse().unwrap())
        .await
        .expect("send UDP packet");

    server.await.expect("server task");
}
