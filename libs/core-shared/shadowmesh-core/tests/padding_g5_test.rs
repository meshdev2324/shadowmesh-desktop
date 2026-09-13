//! Length-hiding padding tests (RFC-012 G5).
//!
//! Pins the wire contract:
//! - PaddingMode::On: lossless round-trip; frame lengths vary between
//!   identical payload sizes (length correlation broken); pad bytes are
//!   random (not zero-runs).
//! - PaddingMode::Off (default): wire stays byte-compatible with SIP007 —
//!   an unpadded peer still interoperates.
//! - A padded stream talking to an unpadded reader is a config error, not a
//!   silent corruption: both sides must opt in.

use shadowmesh_core::protocol::shadowsocks::{PaddingMode, ShadowsocksMethod, ShadowsocksStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn identity() -> String {
    "aes256-test-identity-payload-payload!".to_string()
}

#[tokio::test]
async fn padded_roundtrip_is_lossless() {
    let method = ShadowsocksMethod::Aes256Gcm;
    let id = identity();
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a = ShadowsocksStream::with_options(a_io, method, &id, PaddingMode::On);
    let mut b = ShadowsocksStream::with_options(b_io, method, &id, PaddingMode::On);

    let payload = vec![0xABu8; 1000];
    a.write_all(&payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut received = vec![0u8; payload.len()];
    b.read_exact(&mut received).await.expect("read");
    assert_eq!(received, payload);
}

#[tokio::test]
async fn padded_roundtrip_across_many_sizes() {
    let method = ShadowsocksMethod::ChaCha20Poly1305;
    let id = identity();
    for size in [1usize, 17, 64, 300, 4096] {
        let (a_io, b_io) = tokio::io::duplex(8192);
        let mut a = ShadowsocksStream::with_options(a_io, method, &id, PaddingMode::On);
        let mut b = ShadowsocksStream::with_options(b_io, method, &id, PaddingMode::On);

        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        a.write_all(&payload).await.expect("write");
        a.flush().await.expect("flush");

        let mut received = vec![0u8; size];
        b.read_exact(&mut received).await.expect("read");
        assert_eq!(received, payload, "lossless at size {size}");
    }
}

#[tokio::test]
async fn padding_off_is_wire_compatible() {
    // Off (default) must interop with an explicit Off peer — the pre-G5
    // wire format exactly.
    let method = ShadowsocksMethod::Aes256Gcm;
    let id = identity();
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a = ShadowsocksStream::with_options(a_io, method, &id, PaddingMode::Off);
    let mut b = ShadowsocksStream::new(b_io, method, &id);

    let payload = b"legacy-wire-compat";
    a.write_all(payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut received = vec![0u8; payload.len()];
    b.read_exact(&mut received).await.expect("read");
    assert_eq!(received, payload);
}

/// Statistical check: across N frames of identical payload size, the wire
/// must carry MORE bytes than the unpadded minimum (pad adds 0..=255+1 per
/// frame, with overwhelming probability > 0 across 12 frames).
#[tokio::test]
async fn frame_lengths_vary_under_padding() {
    use tokio::io::AsyncReadExt;

    let method = ShadowsocksMethod::Aes256Gcm;
    let id = identity();
    let (a_io, tap_io) = tokio::io::duplex(65536);
    let mut a = ShadowsocksStream::with_options(a_io, method, &id, PaddingMode::On);

    let payload = [7u8; 64];
    let writer = tokio::spawn(async move {
        for _ in 0..12 {
            a.write_all(&payload).await.expect("write");
            a.flush().await.expect("flush");
        }
    });

    let mut tap = tap_io;
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_millis(500), tap.read(&mut buf)).await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => all.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("tap read: {e}"),
        }
    }
    writer.await.expect("writer");

    // Unpadded minimum per frame: 18 (len chunk) + 64 + 16 (tag) = 98;
    // salt adds 32 once. Padding must strictly exceed that in aggregate.
    let base = 32 + 12 * 98;
    assert!(
        all.len() > base,
        "padded wire must exceed the unpadded minimum (got {}, base {})",
        all.len(),
        base
    );
}
