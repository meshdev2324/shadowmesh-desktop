//! RFC-023 loopback verification: the TUIC v5 outbound is exercised against
//! an in-test server that is an *independent* hand-rolled implementation of
//! the v5 wire format. Byte parsing on the server side is deliberately not
//! shared with the client codec, so a codec bug on either side surfaces as a
//! test failure instead of silent interop drift.

use shadowmesh_core::engine::context::{ConnectionContext, SharedContext};
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::transport::outbound::TuicOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Binds a TCP echo server on 127.0.0.1 and returns its port.
async fn spawn_echo() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = listener.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    port
}

fn test_ctx(destination: Endpoint) -> SharedContext {
    Arc::new(parking_lot::Mutex::new(ConnectionContext::new(ConnectionMetadata::new(destination))))
}

/// A parsed Packet command — fields extracted by independent parsing.
struct ParsedPacket {
    assoc_id: u16,
    pkt_id: u16,
    /// Raw `TYPE + ADDR + PORT` block, reused verbatim in the reply.
    addr_block: Vec<u8>,
    payload: Vec<u8>,
}

/// Hand-rolled strict Packet parser (independent of the client codec).
fn parse_packet(dgram: &[u8]) -> Option<ParsedPacket> {
    if dgram.len() < 10 || dgram[0] != 0x05 || dgram[1] != 0x02 {
        return None;
    }
    let assoc_id = u16::from_be_bytes([dgram[2], dgram[3]]);
    let pkt_id = u16::from_be_bytes([dgram[4], dgram[5]]);
    let size = u16::from_be_bytes([dgram[8], dgram[9]]) as usize;
    let atyp = *dgram.get(10)?;
    let addr_len = match atyp {
        0xff => 1,
        0x00 => 2 + *dgram.get(11)? as usize + 2,
        0x01 => 1 + 4 + 2,
        0x02 => 1 + 16 + 2,
        _ => return None,
    };
    if dgram.len() != 10 + addr_len + size {
        return None;
    }
    Some(ParsedPacket {
        assoc_id,
        pkt_id,
        addr_block: dgram[10..10 + addr_len].to_vec(),
        payload: dgram[10 + addr_len..].to_vec(),
    })
}

/// QUIC stream pair exposed as one Read+Write value for relaying.
struct Relay {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for Relay {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Relay {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Fully qualified: quinn's inherent `poll_write` (WriteError) would
        // otherwise shadow the tokio trait method (io::Error).
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

/// Spawns a spec-conformant TUIC v5 test server on 127.0.0.1 and returns
/// its QUIC port. Authentication is verified by re-deriving the exporter
/// token independently on the server side.
async fn spawn_tuic_server(password: &str, echo_port: u16) -> anyhow::Result<u16> {
    let cert = rcgen::generate_simple_self_signed(vec!["shadowmesh-tuic-edge".into()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], rustls::pki_types::PrivateKeyDer::from(key_der))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let port = endpoint.local_addr()?.port();

    let password = password.to_owned();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            match incoming.await {
                Ok(conn) => {
                    let password = password.clone();
                    tokio::spawn(async move {
                        handle_conn(conn, &password, echo_port).await;
                    });
                }
                Err(_) => continue,
            }
        }
    });
    Ok(port)
}

/// Handles one QUIC connection: Authenticate first, then a datagram echo
/// pump and Connect relays into the TCP echo.
async fn handle_conn(conn: quinn::Connection, password: &str, echo_port: u16) {
    // 1. First unidirectional stream carries the Authenticate command; the
    //    client FINs it, so read to end.
    let Ok(mut uni) = conn.accept_uni().await else { return };
    let Ok(auth) = uni.read_to_end(256).await else { return };
    if auth.len() != 50 || auth[0] != 0x05 || auth[1] != 0x00 {
        conn.close(quinn::VarInt::from_u32(1), b"bad auth frame");
        return;
    }
    let mut expected = [0u8; 32];
    if conn.export_keying_material(&mut expected, &auth[2..18], password.as_bytes()).is_err() {
        conn.close(quinn::VarInt::from_u32(2), b"export failed");
        return;
    }
    if expected[..] != auth[18..50] {
        conn.close(quinn::VarInt::from_u32(3), b"auth mismatch");
        return;
    }

    // 2. Datagram pump: echo every Packet command back from the same
    //    address block with FRAG_TOTAL = 1 (single-fragment replies).
    let pump_conn = conn.clone();
    tokio::spawn(async move {
        while let Ok(dgram) = pump_conn.read_datagram().await {
            if let Some(pkt) = parse_packet(&dgram) {
                let mut reply = Vec::with_capacity(10 + pkt.addr_block.len() + pkt.payload.len());
                reply.extend_from_slice(&[0x05, 0x02]);
                reply.extend_from_slice(&pkt.assoc_id.to_be_bytes());
                reply.extend_from_slice(&pkt.pkt_id.to_be_bytes());
                reply.extend_from_slice(&[1, 0]);
                reply.extend_from_slice(&(pkt.payload.len() as u16).to_be_bytes());
                reply.extend_from_slice(&pkt.addr_block);
                reply.extend_from_slice(&pkt.payload);
                if pump_conn.send_datagram(bytes::Bytes::from(reply)).is_err() {
                    break;
                }
            }
        }
    });

    // 3. Bidirectional streams: each Connect relays into the TCP echo.
    loop {
        let Ok((send, mut recv)) = conn.accept_bi().await else { break };
        tokio::spawn(async move {
            let mut hdr = [0u8; 2];
            if recv.read_exact(&mut hdr).await.is_err() {
                return;
            }
            if hdr[0] != 0x05 || hdr[1] != 0x01 {
                return;
            }
            let mut atyp = [0u8; 1];
            if recv.read_exact(&mut atyp).await.is_err() {
                return;
            }
            let addr_len = match atyp[0] {
                0x00 => {
                    let mut len = [0u8; 1];
                    if recv.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    // The length byte is already consumed above; only the
                    // domain bytes remain before the port.
                    len[0] as usize
                }
                0x01 => 4,
                0x02 => 16,
                _ => return,
            };
            let mut rest = vec![0u8; addr_len + 2];
            if recv.read_exact(&mut rest).await.is_err() {
                return;
            }
            let Ok(mut tcp) = tokio::net::TcpStream::connect(("127.0.0.1", echo_port)).await else {
                return;
            };
            let mut relay = Relay { send, recv };
            let _ = tokio::io::copy_bidirectional(&mut relay, &mut tcp).await;
        });
    }
}

/// TCP relay round-trip and UDP packet round-trip through one shared QUIC
/// session, against the independent in-test server.
#[tokio::test(flavor = "multi_thread")]
async fn tuic_tcp_and_udp_relay_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let echo_port = spawn_echo().await;
    let password = uuid::Uuid::new_v4().to_string();
    let client_uuid = uuid::Uuid::new_v4();
    let server_port = spawn_tuic_server(&password, echo_port).await.expect("test server");

    let ob = TuicOutbound::new(
        "tuic-it".into(),
        "127.0.0.1".into(),
        server_port,
        &client_uuid.to_string(),
        &password,
        None,
        true,
    )
    .expect("outbound construction");

    // TCP relay: Connect header + payload through the QUIC stream pair.
    {
        let ctx = test_ctx(Endpoint::new_domain("echo.shadowmesh.test".into(), echo_port));
        let mut stream = ob.dial_stream(ctx).await.expect("tcp dial");
        stream.write_all(b"hello tuic tcp").await.expect("tcp write");
        let mut buf = [0u8; 14];
        stream.read_exact(&mut buf).await.expect("tcp echo read");
        assert_eq!(&buf, b"hello tuic tcp");
    }

    // UDP relay: Packet datagram out, echoed reply matched by destination.
    {
        let ctx = test_ctx(Endpoint::new_domain("dns.shadowmesh.test".into(), 5353));
        let reply = ob
            .send_packet(ctx, b"query-bytes", SocketAddr::from(([127, 0, 0, 1], 5300)))
            .await
            .expect("udp send");
        assert_eq!(reply, b"query-bytes");
    }
}

/// A wrong password derives a different exporter token; the server closes
/// the connection and no relayed data may ever appear.
#[tokio::test]
async fn tuic_rejects_wrong_password() {
    let _ = tracing_subscriber::fmt::try_init();
    let echo_port = spawn_echo().await;
    let password = uuid::Uuid::new_v4().to_string();
    let wrong_password = uuid::Uuid::new_v4().to_string();
    let client_uuid = uuid::Uuid::new_v4();
    let server_port = spawn_tuic_server(&password, echo_port).await.expect("test server");

    let ob = TuicOutbound::new(
        "tuic-bad".into(),
        "127.0.0.1".into(),
        server_port,
        &client_uuid.to_string(),
        &wrong_password,
        None,
        true,
    )
    .expect("outbound construction");

    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream =
            ob.dial_stream(test_ctx(Endpoint::new_domain("closed.example".into(), 443))).await?;
        stream.write_all(b"payload").await?;
        let mut buf = [0u8; 7];
        let n = stream.read(&mut buf).await?;
        Ok::<usize, anyhow::Error>(n)
    })
    .await;

    match outcome {
        Err(_) => panic!("no terminal state within 3 s"),
        Ok(Err(_)) => {} // connection reset/closed — the expected rejection
        Ok(Ok(n)) => assert_eq!(n, 0, "server must not relay data for bad credentials"),
    }
}

/// Reserves an ephemeral UDP port for the inbound listener (small
/// bind-and-release race window, acceptable for loopback tests).
async fn reserve_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("reserve bind");
    socket.local_addr().expect("reserve addr").port()
}

/// The production `TuicInbound` exercised end-to-end through the engine
/// event seam: a mock engine consumer relays `NewStream` into the TCP echo
/// and echoes `UdpPacket` payloads back, so client role and server role of
/// RFC-023 meet over the real event interface.
#[tokio::test(flavor = "multi_thread")]
async fn tuic_real_inbound_engine_seam_roundtrip() {
    use shadowmesh_core::engine::actor::EngineHandle;
    use shadowmesh_core::engine::events::EngineEvent;
    use shadowmesh_core::transport::inbound::TuicInbound;
    use shadowmesh_core::transport::traits::InboundListener;

    let _ = tracing_subscriber::fmt::try_init();
    let echo_port = spawn_echo().await;
    let password = uuid::Uuid::new_v4().to_string();
    let client_uuid = uuid::Uuid::new_v4();

    let cert = rcgen::generate_simple_self_signed(vec!["shadowmesh-tuic-edge".into()])
        .expect("cert generation");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    // Mock engine: drain events and serve them from the local echo.
    let (event_tx, event_rx) = async_channel::bounded::<EngineEvent>(256);
    let handle = EngineHandle::new(event_tx);
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match event {
                EngineEvent::NewStream { context, mut stream } => {
                    let destination = context.lock().metadata.identity.destination.clone();
                    let port = destination.port;
                    tokio::spawn(async move {
                        if let Ok(mut tcp) =
                            tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                        {
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                        }
                    });
                }
                EngineEvent::UdpPacket { payload, reply: Some(reply), .. } => {
                    let _ = reply.send(Some(payload));
                }
                _ => {}
            }
        }
    });

    let port = reserve_udp_port().await;
    let inbound = TuicInbound::new(
        "tuic-edge".into(),
        format!("127.0.0.1:{port}"),
        &client_uuid.to_string(),
        &password,
        cert_path.to_str().expect("cert path").to_owned(),
        key_path.to_str().expect("key path").to_owned(),
        handle,
    )
    .expect("inbound construction");
    tokio::spawn(async move {
        if let Err(e) = inbound.listen().await {
            panic!("tuic inbound failed: {e:#}");
        }
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ob = TuicOutbound::new(
        "tuic-client".into(),
        "127.0.0.1".into(),
        port,
        &client_uuid.to_string(),
        &password,
        None,
        true,
    )
    .expect("outbound construction");

    // TCP relay through the real inbound into the engine seam → echo.
    {
        let ctx = test_ctx(Endpoint::new_domain("echo.shadowmesh.test".into(), echo_port));
        let mut stream = ob.dial_stream(ctx).await.expect("tcp dial");
        stream.write_all(b"through the inbound").await.expect("tcp write");
        let mut buf = [0u8; 19];
        stream.read_exact(&mut buf).await.expect("tcp echo read");
        assert_eq!(&buf, b"through the inbound");
    }

    // UDP relay through the real inbound's pump → engine → reply datagram.
    {
        let ctx = test_ctx(Endpoint::new_domain("dns.shadowmesh.test".into(), 5353));
        let reply = ob
            .send_packet(ctx, b"engine-seam-query", SocketAddr::from(([127, 0, 0, 1], 5300)))
            .await
            .expect("udp send");
        assert_eq!(reply, b"engine-seam-query");
    }
}
