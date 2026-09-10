//! REALITY server ↔ client interop tests (RFC-015 §6.1).
//!
//! The acid test for the native edge: the REAL `RealityTlsStream` client
//! (the exact code path the Android APK ships) must complete a full TLS 1.3
//! handshake against the new `reality_server::accept`, exchange application
//! data, and — on authentication failure — be transparently relayed to the
//! masquerade target (active-probing resistance).
//!
//! Implementation Source:
//! - Specifications: RFC 8446; this repo's `reality_tls.rs` client contract.
//! - Security considerations: per-run key material from the OS CSPRNG; all
//!   traffic is loopback.

use base64::Engine as _;
use shadowmesh_core::transport::reality_server::{self, Accepted};
use shadowmesh_core::transport::reality_tls::RealityTlsStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn x25519_pair() -> (Vec<u8>, Vec<u8>) {
    shadowmesh_common::crypto::generate_x25519_keypair()
}

/// Spawns a TCP echo server used as both the app destination and the
/// masquerade target for fallback.
async fn spawn_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, task)
}

/// Spawns the REALITY server: authenticated streams echo app data;
/// fallbacks are relayed transparently to the decoy.
async fn spawn_reality_server(priv_hex: String, short_ids: Vec<String>, decoy_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let priv_hex = priv_hex.clone();
            let short_ids = short_ids.clone();
            tokio::spawn(async move {
                let config = shadowmesh_core::RealityServerConfig {
                    private_key: priv_hex,
                    short_ids,
                    sni_target: format!("127.0.0.1:{decoy_port}"),
                };
                match reality_server::accept(sock, &config).await {
                    Accepted::Stream(mut stream) => {
                        // Echo application data back over the REALITY session.
                        let mut buf = [0u8; 8192];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Accepted::Fallback(sock, buffered) => {
                        // Active probing: relay raw bytes to the masquerade.
                        if let Ok(mut decoy) = TcpStream::connect(("127.0.0.1", decoy_port)).await {
                            use tokio::io::copy_bidirectional;
                            let _ = decoy.write_all(&buffered).await;
                            let _ = copy_bidirectional(&mut { sock }, &mut decoy).await;
                        }
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn reality_client_server_interop_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let (priv_key, pub_key) = x25519_pair();
    let short_id = hex::encode(shadowmesh_core::secure_random_bytes(8).expect("CSPRNG"));

    let port =
        spawn_reality_server(hex::encode(&priv_key), vec![short_id.clone()], echo_port).await;

    // Client speaks the exact Android wire protocol.
    let sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let mut tls = RealityTlsStream::connect(
        sock,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_key),
        &short_id,
        "www.example.com",
    )
    .await
    .expect("REALITY handshake must complete against the native server");

    tls.write_app(b"ping-over-reality").await.expect("write_app");
    let reply = tls.read_app().await.expect("read_app").expect("payload");
    assert_eq!(reply, b"ping-over-reality", "app data must roundtrip the REALITY session");

    // Second exchange: sequence numbers must advance correctly.
    tls.write_app(b"second").await.expect("write_app 2");
    let reply2 = tls.read_app().await.expect("read_app 2").expect("payload 2");
    assert_eq!(reply2, b"second");

    echo_task.abort();
}

#[tokio::test]
async fn reality_wrong_short_id_falls_back_to_masquerade() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let (priv_key, pub_key) = x25519_pair();
    let good_sid = hex::encode(shadowmesh_core::secure_random_bytes(8).expect("CSPRNG"));
    let bad_sid = hex::encode(shadowmesh_core::secure_random_bytes(8).expect("CSPRNG"));

    let port = spawn_reality_server(hex::encode(&priv_key), vec![good_sid], echo_port).await;

    let sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let result = RealityTlsStream::connect(
        sock,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_key),
        &bad_sid,
        "www.example.com",
    )
    .await;

    // The client must NOT be served VLESS: it either sees the decoy's echo
    // (garbage ServerHello) or an alert — in every case, no REALITY session.
    assert!(result.is_err(), "wrong short_id must never authenticate");
    echo_task.abort();
}

#[tokio::test]
async fn reality_wrong_key_falls_back_to_masquerade() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let (priv_key, _) = x25519_pair();
    let (_other_priv, other_pub) = x25519_pair();
    let short_id = hex::encode(shadowmesh_core::secure_random_bytes(8).expect("CSPRNG"));

    let port =
        spawn_reality_server(hex::encode(&priv_key), vec![short_id.clone()], echo_port).await;

    let sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let result = RealityTlsStream::connect(
        sock,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&other_pub),
        &short_id,
        "www.example.com",
    )
    .await;

    assert!(result.is_err(), "wrong REALITY public key must never authenticate");
    echo_task.abort();
}
