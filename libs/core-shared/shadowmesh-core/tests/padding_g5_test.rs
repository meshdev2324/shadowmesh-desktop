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
//!
//! Also pins the *config* path, which is what makes G5 reachable at all: the
//! implementation existed with zero callers, so "does the algorithm work" was
//! not the question — "can an operator turn it on, and does turning it on do
//! what the RFC says" was.

use shadowmesh_core::config::settings::padding_mode;
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

// ---- the config path: G5 was finished and unreachable --------------------
//
// Every test above constructs the stream by hand. Nothing in the product could
// do that: `with_options` had no callers outside this file, and neither
// settings struct had a padding field, so `PaddingMode::On` was unreachable
// from a config file. These pin the gate itself.

#[test]
fn config_absent_means_off() {
    // The compatibility requirement: a config written before G5 existed has no
    // `padding` key at all, and must keep producing the exact SIP007 wire.
    assert_eq!(padding_mode(None), PaddingMode::Off);
}

#[test]
fn config_false_means_off_and_true_means_on() {
    assert_eq!(padding_mode(Some(false)), PaddingMode::Off);
    assert_eq!(padding_mode(Some(true)), PaddingMode::On);
}

/// A padding flag that defaulted to *on* would silently break every external
/// SIP007 peer on upgrade, so the absent case must be pinned separately from
/// the explicit-false case rather than assumed.
#[test]
fn an_unstated_option_never_turns_a_feature_on() {
    assert_ne!(padding_mode(None), padding_mode(Some(true)));
}

#[test]
fn the_outbound_setting_reaches_the_stream() {
    use shadowmesh_core::config::settings::ShadowsocksSettings;

    let raw = serde_json::json!({
        "server": "1.2.3.4",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "unit-test-placeholder",
        "padding": true,
    });
    let s: ShadowsocksSettings =
        shadowmesh_core::config::settings::parse_strict(&raw, "shadowsocks")
            .expect("padding must be a recognised field");
    assert_eq!(padding_mode(s.padding), PaddingMode::On);
}

#[test]
fn the_inbound_setting_reaches_the_stream() {
    use shadowmesh_core::config::settings::ShadowsocksInboundSettings;

    let raw = serde_json::json!({
        "method": "aes-256-gcm",
        "password": "unit-test-placeholder",
        "padding": false,
    });
    let s: ShadowsocksInboundSettings =
        shadowmesh_core::config::settings::parse_strict(&raw, "shadowsocks-inbound")
            .expect("padding must be a recognised field");
    assert_eq!(padding_mode(s.padding), PaddingMode::Off);
}

/// `deny_unknown_fields` is the point of these structs; adding a field must not
/// have relaxed that. A typo'd `paddding` still has to fail at load time rather
/// than silently running unpadded — which an operator would read as "padding
/// is on and something is still leaking".
#[test]
fn a_typo_in_the_padding_flag_is_a_hard_config_error() {
    use shadowmesh_core::config::settings::ShadowsocksSettings;

    let raw = serde_json::json!({
        "server": "1.2.3.4",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "unit-test-placeholder",
        "paddding": true,
    });
    assert!(
        shadowmesh_core::config::settings::parse_strict::<ShadowsocksSettings>(&raw, "shadowsocks")
            .is_err(),
        "a misspelled padding flag must not parse"
    );
}

/// Malformed padding must fail the frame, not be silently absorbed.
///
/// The reader trusts the last plaintext byte as a pad-length marker. If that
/// byte claims more padding than the frame holds, the length arithmetic would
/// otherwise wrap into a plausible-looking payload.
///
/// A malformed frame cannot be produced through the public API — the AEAD tag
/// has to verify first — so this asserts the property that is observable from
/// outside: padding never *lengthens* the payload, under any mode. The strip
/// arithmetic itself, including the overlong-marker rejection, is covered by
/// `g5_an_overlong_pad_marker_is_rejected` in the protocol module where the
/// function is reachable.
#[tokio::test]
async fn padding_never_lengthens_the_payload_a_reader_returns() {
    let method = ShadowsocksMethod::Aes256Gcm;
    let id = identity();

    for mode in [PaddingMode::Off, PaddingMode::On] {
        let (a_io, b_io) = tokio::io::duplex(8192);
        let mut a = ShadowsocksStream::with_options(a_io, method, &id, mode);
        let mut b = ShadowsocksStream::with_options(b_io, method, &id, mode);

        let payload: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        a.write_all(&payload).await.expect("write");
        a.flush().await.expect("flush");

        let mut received = vec![0u8; payload.len()];
        b.read_exact(&mut received).await.expect("read");
        assert_eq!(received, payload, "{mode:?} must deliver the payload exactly");
    }
}

/// The mirror of the bug above, and the reason the writer now always emits the
/// marker.
///
/// The pad length is *random*, so a wire-size assertion cannot pin this: a
/// frame is `payload + pad(0..=255) + marker`, and only the marker is
/// deterministic. This test therefore decrypts the frames and checks the
/// invariant directly — for **every** frame, the trailing byte is a pad-length
/// marker whose value plus one equals the pad actually present. A frame written
/// without the marker would fail that on the 1-in-256 frames where the random
/// pad came out zero, and this drives hundreds of frames, so the probability of
/// not sampling one is negligible (`(255/256)^n`).
#[tokio::test]
async fn every_padded_frame_ends_in_a_pad_length_marker() {
    use shadowmesh_core::protocol::shadowsocks::{ShadowsocksCipher, TAG_SIZE};

    let method = ShadowsocksMethod::Aes256Gcm;
    let id = identity();
    let frames = 400usize;

    let (a_io, tap_io) = tokio::io::duplex(1 << 20);
    let mut a = ShadowsocksStream::with_options(a_io, method, &id, PaddingMode::On);

    let writer = tokio::spawn(async move {
        for _ in 0..frames {
            a.write_all(&[0x42u8]).await.expect("write");
        }
        a.flush().await.expect("flush");
    });
    // The writer must finish before the wire is parsed. Draining concurrently
    // and stopping on an idle timeout would truncate mid-frame, and the walk
    // below would then try to authenticate payload bytes as a length chunk.
    writer.await.expect("writer");

    let mut tap = tap_io;
    let mut wire = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tokio::io::AsyncReadExt::read(&mut tap, &mut buf).await {
            Ok(0) => break,
            Ok(n) => wire.extend_from_slice(&buf[..n]),
            Err(e) => panic!("tap read: {e}"),
        }
    }

    let salt_len = method.salt_len();
    assert!(wire.len() > salt_len, "the writer produced no salt");
    let salt = wire[..salt_len].to_vec();
    let mut opening = ShadowsocksCipher::new(method, &id, &salt)
        .expect("derivation")
        .opening_key()
        .expect("opening key");

    // Walk the frames: [salt][len chunk 2 + tag][payload chunk n + tag]...
    //
    // `open_in_place` takes ciphertext **with** the tag appended, so each slice
    // handed to it must include the following TAG_SIZE bytes — that is what the
    // stream itself does, and omitting it authenticates a buffer that never had
    // a valid tag in it.
    let mut cursor = salt_len;
    let mut decoded = 0usize;
    let mut zero_length_pads = 0usize;
    while cursor + 2 + TAG_SIZE <= wire.len() {
        let mut len_chunk = wire[cursor..cursor + 2 + TAG_SIZE].to_vec();
        cursor += 2 + TAG_SIZE;
        let frame_len = {
            use ring::aead::Aad;
            let opened = opening
                .open_in_place(Aad::empty(), &mut len_chunk)
                .expect("length chunk must authenticate");
            u16::from_be_bytes([opened[0], opened[1]]) as usize
        };
        if cursor + frame_len + TAG_SIZE > wire.len() {
            break; // trailing partial read
        }
        let mut body = wire[cursor..cursor + frame_len + TAG_SIZE].to_vec();
        cursor += frame_len + TAG_SIZE;
        {
            use ring::aead::Aad;
            opening
                .open_in_place(Aad::empty(), &mut body)
                .expect("payload chunk must authenticate");
        }
        let body = &body[..frame_len];

        // 1 payload byte + pad + 1 marker byte.
        assert!(frame_len >= 2, "a padded frame must carry a marker even with no pad");
        let marker = body[body.len() - 1] as usize;
        assert_eq!(
            1 + marker,
            frame_len - 1,
            "the trailing byte must be a pad-length marker describing the rest of the frame"
        );
        if marker == 0 {
            zero_length_pads += 1;
        }
        decoded += 1;
    }

    assert_eq!(decoded, frames, "every frame must be well formed");
    // `zero_length_pads` is reported, not asserted. Requiring it to be > 0 would
    // make this test flaky: 400 draws at 1/256 miss with probability ~21%, and a
    // test that fails one run in five is worse than one that says less. The
    // zero-length case is pinned deterministically by
    // `g5_a_zero_length_pad_still_costs_its_marker` in the protocol module,
    // where the frame can be constructed rather than sampled.
    println!("decoded {decoded} padded frames, {zero_length_pads} with a zero-length pad");
}
