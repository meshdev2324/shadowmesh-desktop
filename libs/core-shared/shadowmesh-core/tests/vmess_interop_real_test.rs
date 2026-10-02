//! End-to-end VMess inbound ↔ outbound interop tests.
//!
//! Implementation Source:
//! - Specification: VMess transport (RFC-010 internal spec, public VMess wire format)
//! - Relevant sections: AuthID derivation, AES-128-CFB8 header, HMAC-MD5 checksum,
//!   AEAD chunked data stream.
//! - Security considerations: rejects invalid AuthID, verifies header checksum,
//!   AEAD chunk authentication.
//!
//! Unlike the mock-server test in `vmess_integration_test.rs`, this suite drives
//! the *real* `VmessInbound` listener against the *real* `VmessOutbound` dialer,
//! which is what exposes header/data stream desynchronization bugs.

use shadowmesh_core::engine::actor::EngineHandle;
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::events::EngineEvent;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::transport::inbound::vmess::VmessInbound;
use shadowmesh_core::transport::outbound::vmess::VmessOutbound;
use shadowmesh_core::transport::traits::{InboundListener, OutboundDialer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Spawns a VmessInbound on an ephemeral port and returns its address.
async fn spawn_vmess_inbound(
    uuid_str: &str,
) -> (std::net::SocketAddr, async_channel::Receiver<EngineEvent>) {
    let (event_tx, event_rx) = async_channel::unbounded();
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let addr = probe.local_addr().expect("local addr");
    drop(probe);

    let inbound = VmessInbound::new(
        "vmess-in-test".to_string(),
        addr.to_string(),
        uuid_str,
        EngineHandle::new(event_tx),
    )
    .expect("build inbound");

    tokio::spawn(async move {
        if let Err(e) = inbound.listen().await {
            eprintln!("vmess inbound listener exited: {e:?}");
        }
    });

    // Wait until the inbound has actually bound the port (we released the
    // probe listener above, so the real bind happens asynchronously).
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    (addr, event_rx)
}

#[tokio::test]
async fn test_vmess_real_inbound_outbound_data_roundtrip() {
    let uuid = Uuid::new_v4();
    let (server_addr, event_rx) = spawn_vmess_inbound(&uuid.to_string()).await;

    // Destination echo server: the "real" target behind the proxy.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = echo_listener.accept().await {
            let mut buf = [0u8; 4096];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(&buf[..n]).await;
            }
        }
    });

    // Engine event consumer: forward every dispatched stream to the echo target.
    let forward_addr = echo_addr;
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            if let EngineEvent::NewStream { mut stream, .. } = event {
                tokio::spawn(async move {
                    if let Ok(mut target) = tokio::net::TcpStream::connect(forward_addr).await {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                    }
                });
            }
        }
    });

    let outbound = VmessOutbound::new(
        "vmess-out-test".to_string(),
        "127.0.0.1".to_string(),
        server_addr.port(),
        &uuid.to_string(),
        "aes-128-gcm".to_string(),
    )
    .expect("build outbound");

    let metadata = ConnectionMetadata::new(Endpoint::new_domain("echo.internal".to_string(), 443));
    let context = Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)));

    let mut stream = outbound.dial_stream(context).await.expect("dial");
    stream.write_all(b"roundtrip-through-real-inbound").await.expect("write");
    stream.flush().await.expect("flush");

    const PAYLOAD: &[u8] = b"roundtrip-through-real-inbound";
    let mut response = [0u8; PAYLOAD.len()];
    stream.read_exact(&mut response).await.expect("read response through AEAD stream");
    assert_eq!(&response, PAYLOAD);
}

#[tokio::test]
async fn test_vmess_rejects_wrong_uuid() {
    let server_uuid = Uuid::new_v4();
    let (server_addr, _rx) = spawn_vmess_inbound(&server_uuid.to_string()).await;

    let client_uuid = Uuid::new_v4();
    let outbound = VmessOutbound::new(
        "vmess-out-bad".to_string(),
        "127.0.0.1".to_string(),
        server_addr.port(),
        &client_uuid.to_string(),
        "aes-128-gcm".to_string(),
    )
    .expect("build outbound");

    let metadata = ConnectionMetadata::new(Endpoint::new_domain("x.test".to_string(), 80));
    let context = Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)));

    let mut stream = outbound.dial_stream(context).await.expect("tcp dial");
    // Data phase must fail: the inbound will not find a valid AuthID.
    stream.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 8];
    let result = stream.read(&mut buf).await;
    assert!(
        result.is_err() || buf.iter().all(|&b| b == 0),
        "expected failure or closed stream with wrong UUID"
    );
}
