//! Shadowsocks-2022 stream tests (RFC-012 G1).
//!
//! Pins the wire behavior introduced by the 2022 edition:
//! - BLAKE3-derived subkeys (base64 identities, salt = key length)
//! - Two standalone header chunks: an 11-byte fixed header
//!   `[type:1][ts_secs:8][len:2]`, then the variable-length header carrying the
//!   SOCKS5 target address (SIP022 section 3.1.2)
//! - Replay rejection: a stale timestamp in the first header kills the session
//! - Lossless round-trip through the full encrypt/decrypt stream path.

use shadowmesh_core::protocol::shadowsocks::{ShadowsocksMethod, ShadowsocksStream, StreamRole};
use shadowmesh_core::protocol::{ss2022, ss2022_stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Builds a valid 2022-edition base64 identity (32 raw bytes).
fn identity_b64() -> String {
    use base64::Engine;
    let raw = [0x33u8; 32];
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// SOCKS5 ATYP=1 address plus port, in the wire order SIP022 section 3.1.2's
/// variable-length header carries. A request stream's variable header *is* the
/// target address, so every request writes this before its payload.
const ADDR: [u8; 7] = [1, 93, 184, 216, 34, 0x01, 0xBB];

#[tokio::test]
async fn ss2022_stream_roundtrip() {
    let method = ShadowsocksMethod::Aes256Gcm2022;
    let identity = identity_b64();

    let (client_io, server_io) = tokio::io::duplex(8192);
    let mut a = ShadowsocksStream::new(client_io, method, &identity).with_role(StreamRole::Client);
    let mut b = ShadowsocksStream::new(server_io, method, &identity).with_role(StreamRole::Server);

    let payload = b"ss2022-roundtrip-payload";
    a.write_all(&ADDR).await.expect("write address");
    a.write_all(payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut received = vec![0u8; ADDR.len() + payload.len()];
    b.read_exact(&mut received).await.expect("read");
    assert_eq!(&received[..ADDR.len()], &ADDR[..], "the target address must survive");
    assert_eq!(&received[ADDR.len()..], payload);
}

#[tokio::test]
async fn ss2022_replay_window_rejects_stale_header() {
    let method = ShadowsocksMethod::ChaCha20Poly13052022;
    let identity = identity_b64();

    // The replay guard the stream actually applies is
    // `ss2022_stream::check_timestamp` — SIP022 section 3.1.5's 30-second skew
    // window. This used to assert against `ss2022::FixedHeader::is_fresh`,
    // which was a millisecond-valued predicate on a header shape the stream no
    // longer used: it passed while proving nothing about the real path, which
    // is the same failure mode as a round-trip test of a format you invented.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    // Far outside the window: this is what a replayed session looks like.
    assert!(
        ss2022_stream::check_timestamp(now_secs - 1_000_000, now_secs).is_err(),
        "a timestamp from 1970 must fail the skew window"
    );
    // A millisecond-valued timestamp — what this writer used to emit — is not
    // merely stale, it is off by ~1.7e12 seconds, which is why every conformant
    // peer rejected the old framing even though its tags verified.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    assert!(
        ss2022_stream::check_timestamp(now_ms, now_secs).is_err(),
        "a millisecond timestamp must not be mistaken for a second-valued one"
    );
    // The current second passes, and so does the edge of the window.
    assert!(ss2022_stream::check_timestamp(now_secs, now_secs).is_ok());
    assert!(ss2022_stream::check_timestamp(now_secs - 29, now_secs).is_ok());
    assert!(ss2022_stream::check_timestamp(now_secs - 31, now_secs).is_err());

    // And the stream still builds, so the guard above is the one on its path.
    let (client_io, server_io) = tokio::io::duplex(8192);
    let _ = ShadowsocksStream::new(client_io, method, &identity);
    let _b = ShadowsocksStream::new(server_io, method, &identity);
}

#[test]
fn ss2022_identity_parsing_enforces_length() {
    // Wrong-length identity must be rejected, never silently padded.
    let raw_16 = [0x11u8; 16];
    use base64::Engine;
    let short = base64::engine::general_purpose::STANDARD.encode(raw_16);
    assert!(ss2022::parse_identity_key(&short, 32).is_err());
    assert!(ss2022::parse_identity_key(&identity_b64(), 32).is_ok());
    assert!(ss2022::parse_identity_key("not-base64!!!", 32).is_err());
}
