//! Backpressure regression tests for the VMess AEAD chunk stream.
//!
//! Historical bug: when a frame exceeded the transport's buffer capacity, the
//! writer state machine re-encrypted the same payload on every `write_all`
//! retry, producing duplicate frames on the wire (reader desync) and a
//! never-completing write. These tests pin the `AsyncWrite` contract: success
//! is only reported for fully flushed frames, and every payload size —
//! including frames larger than a duplex pipe's capacity — round-trips with a
//! concurrent reader. Every stage is bounded by a 5s timeout so a regression
//! fails fast instead of hanging CI.

use shadowmesh_core::transport::outbound::vmess::VmessStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn duplex_partial_write_16k() {
    let (mut a, mut b) = tokio::io::duplex(8192);
    let payload = vec![7u8; 16418];

    let writer = tokio::task::spawn(async move {
        a.write_all(&payload).await.expect("write_all");
    });

    let mut got = vec![0u8; 16418];
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        b.read_exact(&mut got).await.expect("read_exact");
    })
    .await
    .expect("duplex read completed within 5s");
    writer.await.expect("writer task");
}

#[tokio::test]
async fn vmess_roundtrip_just_under_duplex() {
    // 8156 bytes + 36 framing = 8192 exactly fits.
    vmess_roundtrip(8156).await;
}

#[tokio::test]
async fn vmess_roundtrip_over_duplex() {
    // 16384 bytes -> frame 16420 > 8192 duplex capacity: requires concurrent
    // reader + partial writes + in-flight frame state.
    vmess_roundtrip(16384).await;
}

#[tokio::test]
async fn vmess_roundtrip_odd_sizes() {
    for size in [1usize, 17, 36, 37, 8156, 8157, 8192, 10000, 16384] {
        vmess_roundtrip(size).await;
    }
}

async fn vmess_roundtrip(size: usize) {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let (client_io, server_io) = tokio::io::duplex(8192);
    let mut a = VmessStream::new(client_io, key, iv).unwrap();
    let mut b = VmessStream::new(server_io, key, iv).unwrap();

    let payload_out = payload.clone();
    let writer = tokio::task::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            a.write_all(&payload_out).await.expect("write_all");
            a.flush().await.expect("flush");
        })
        .await
        .expect("write side completed within 5s");
    });

    let mut received = vec![0u8; size];
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        b.read_exact(&mut received).await.expect("read_exact");
    })
    .await
    .expect("read side completed within 5s");

    writer.await.expect("writer join");
    assert_eq!(received, payload, "roundtrip mismatch at size {size}");
}
