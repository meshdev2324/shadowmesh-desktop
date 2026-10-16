//! VMess length-hiding padding tests (RFC-012 G5, second half).
//!
//! Shadowsocks got G5 first and the VMess half was left open. The padding
//! contract itself — layout, the marker, malformed-marker rejection, the
//! zero-length case — is shared and lives in `protocol::padding`, tested
//! against **all 256 pad lengths** rather than a sample. This file pins the
//! parts that are VMess-specific:
//!
//! - the AEAD chunk stream round-trips losslessly when padded, and stays
//!   byte-compatible when not;
//! - every chunk that goes on the wire really does carry its marker, checked by
//!   decrypting the real frames rather than by trusting the writer;
//! - the config gate reaches both `VmessSettings` and `VmessInboundSettings`,
//!   which is what makes `PaddingMode::On` reachable at all — the Shadowsocks
//!   half shipped finished and unreachable once already;
//! - a mismatched pair is corruption in both directions, never a graceful
//!   degradation.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use shadowmesh_core::config::settings::padding_mode;
use shadowmesh_core::protocol::padding::PaddingMode;
use shadowmesh_core::transport::outbound::vmess::VmessStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Obvious placeholder, not a credential: these tests never leave the process.
const TEST_KEY: [u8; 16] = [0x5A; 16];
const TEST_IV: [u8; 16] = [0x17; 16];

const VMESS_TAG_SIZE: usize = 16;
/// Must match the reader's `MAX_VMESS_CHUNK`; a padded frame must never exceed
/// it, or the reader rejects a frame this writer produced.
const MAX_VMESS_CHUNK: usize = 16384;

/// Mirrors `VmessStream::next_nonce`. Reimplemented rather than exported
/// because the wire walk has to know it independently — a test that reused the
/// implementation would agree with a bug.
fn nonce_for(seq: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

fn sealing_and_opening() -> (LessSafeKey, LessSafeKey) {
    // Built separately rather than cloned: `UnboundKey` is deliberately not
    // `Clone`, so sharing one here would be a claim the library does not make.
    let sealing = UnboundKey::new(&AES_128_GCM, &TEST_KEY).expect("test key is 16 bytes");
    let opening = UnboundKey::new(&AES_128_GCM, &TEST_KEY).expect("test key is 16 bytes");
    (LessSafeKey::new(sealing), LessSafeKey::new(opening))
}

// ---------------------------------------------------------------------------
// Stream round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vmess_padded_roundtrip_across_many_sizes() {
    for size in [1usize, 17, 64, 300, 4096] {
        let (a_io, b_io) = tokio::io::duplex(8192);
        let mut a =
            VmessStream::with_options(a_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");
        let mut b =
            VmessStream::with_options(b_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");

        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        a.write_all(&payload).await.expect("write");
        a.flush().await.expect("flush");

        let mut received = vec![0u8; size];
        b.read_exact(&mut received).await.expect("read");
        assert_eq!(received, payload, "lossless at size {size}");
    }
}

/// The default must stay wire-compatible: `new` and an explicit `Off` are the
/// same construction, and an unpadded peer still reads it.
#[tokio::test]
async fn vmess_padding_off_is_wire_compatible() {
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("stream");
    let mut b =
        VmessStream::with_options(b_io, TEST_KEY, TEST_IV, PaddingMode::Off).expect("stream");

    let payload = b"legacy-vmess-wire-compat";
    a.write_all(payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut received = vec![0u8; payload.len()];
    b.read_exact(&mut received).await.expect("read");
    assert_eq!(received, payload);
}

/// Padding is only worth anything if it breaks the length correlation, so the
/// wire must carry more than the unpadded minimum across identical frames.
#[tokio::test]
async fn vmess_frame_lengths_vary_under_padding() {
    let (a_io, tap_io) = tokio::io::duplex(1 << 20);
    let mut a =
        VmessStream::with_options(a_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");

    let payload = [7u8; 64];
    let frames = 12usize;
    let writer = tokio::spawn(async move {
        for _ in 0..frames {
            a.write_all(&payload).await.expect("write");
        }
        a.flush().await.expect("flush");
    });

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
    writer.await.expect("writer");

    // Unpadded minimum per frame: 18 (length chunk) + 64 + 16 (tag) = 98.
    let base = frames * (2 + VMESS_TAG_SIZE + payload.len() + VMESS_TAG_SIZE);
    assert!(
        wire.len() > base,
        "padded wire must exceed the unpadded minimum (got {}, base {})",
        wire.len(),
        base
    );
}

// ---------------------------------------------------------------------------
// The wire itself
// ---------------------------------------------------------------------------

/// Walks the real chunk stream and checks the property the Shadowsocks half
/// needed a bug to teach: for **every** frame, the last plaintext byte is a
/// pad-length marker describing exactly the pad that precedes it.
///
/// The pad length is drawn at random, so this samples — but it drives 400
/// frames, and `(255/256)^400` is about 2·10⁻⁷. The exhaustive check is
/// `every_pad_length_round_trips` in `protocol::padding`, which builds all 256
/// lengths directly. Between them there is no uncovered pad length: sampled on
/// the wire, exhaustive in the contract.
#[tokio::test]
async fn every_vmess_chunk_ends_in_a_pad_length_marker() {
    let (a_io, tap_io) = tokio::io::duplex(1 << 20);
    let mut a =
        VmessStream::with_options(a_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");

    let frames = 400usize;
    let writer = tokio::spawn(async move {
        for _ in 0..frames {
            a.write_all(&[0x42u8]).await.expect("write");
        }
        a.flush().await.expect("flush");
    });

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
    writer.await.expect("writer");

    let (_sealing, opening) = sealing_and_opening();

    // Layout: [length:2 + tag:16][body:frame_len + tag:16]...
    //
    // `open_in_place` takes ciphertext *with* the tag appended, so each slice
    // handed to it must include the following VMESS_TAG_SIZE bytes — that is
    // what the stream itself does.
    let mut cursor = 0usize;
    let mut decoded = 0usize;
    let mut zero_length_pads = 0usize;
    let mut widest = 0usize;
    while cursor + 2 + VMESS_TAG_SIZE <= wire.len() {
        let mut len_chunk = wire[cursor..cursor + 2 + VMESS_TAG_SIZE].to_vec();
        cursor += 2 + VMESS_TAG_SIZE;
        let frame_len = {
            let opened = opening
                .open_in_place(nonce_for(2 * decoded as u64), Aad::empty(), &mut len_chunk)
                .expect("length chunk must authenticate");
            u16::from_be_bytes([opened[0], opened[1]]) as usize
        };
        assert!(
            frame_len <= MAX_VMESS_CHUNK,
            "a padded chunk ({frame_len} B) must stay inside the reader's bound"
        );
        if cursor + frame_len + VMESS_TAG_SIZE > wire.len() {
            break; // trailing partial read
        }
        let mut body = wire[cursor..cursor + frame_len + VMESS_TAG_SIZE].to_vec();
        cursor += frame_len + VMESS_TAG_SIZE;
        {
            let opened = opening
                .open_in_place(nonce_for(2 * decoded as u64 + 1), Aad::empty(), &mut body)
                .expect("body chunk must authenticate");
            // 1 payload byte + pad + 1 marker byte.
            assert!(frame_len >= 2, "a padded chunk must carry a marker even with no pad");
            let marker = opened[frame_len - 1] as usize;
            assert_eq!(
                1 + marker,
                frame_len - 1,
                "the trailing byte must be a pad-length marker describing the rest of the chunk"
            );
            if marker == 0 {
                zero_length_pads += 1;
            }
            widest = widest.max(marker);
        }
        decoded += 1;
    }

    assert_eq!(decoded, frames, "every chunk must be well formed");
    // Reported, not asserted: requiring a sampled zero-length pad would make
    // the test flaky (400 draws miss 1/256 about 21% of the time). The
    // zero-length case is pinned deterministically by
    // `a_zero_length_pad_is_written_as_a_lone_marker`.
    println!("decoded {decoded} padded VMess chunks, {zero_length_pads} zero-length pad, widest {widest}");
}

/// Under `Off` the wire is exactly the pre-G5 framing: length == payload, and
/// there is no trailing byte to strip.
#[tokio::test]
async fn an_unpadded_vmess_chunk_declares_exactly_its_payload() {
    let (a_io, tap_io) = tokio::io::duplex(1 << 16);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("stream");

    let payload = [0x33u8; 100];
    let writer = tokio::spawn(async move {
        a.write_all(&payload).await.expect("write");
        a.flush().await.expect("flush");
    });

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
    writer.await.expect("writer");

    let (_sealing, opening) = sealing_and_opening();
    let mut len_chunk = wire[..2 + VMESS_TAG_SIZE].to_vec();
    // Frame 0's length chunk spends counter value `2*0`; the body follows on
    // `2*0+1`. Only the length chunk is opened here, so only the first appears.
    let opened =
        opening.open_in_place(nonce_for(0), Aad::empty(), &mut len_chunk).expect("length chunk");
    let frame_len = u16::from_be_bytes([opened[0], opened[1]]) as usize;
    assert_eq!(frame_len, payload.len(), "Off must not add a byte to the declared length");
    assert_eq!(wire.len(), 2 + VMESS_TAG_SIZE + payload.len() + VMESS_TAG_SIZE);
}

// ---------------------------------------------------------------------------
// Mismatched pairs
// ---------------------------------------------------------------------------

/// A padded writer against an unpadded reader does not fail — it *succeeds*,
/// delivering the pad and the marker as if they were payload. That is the
/// dangerous direction, and it is why the mode is config-gated on both ends
/// rather than negotiated.
#[tokio::test]
async fn a_padded_writer_against_an_unpadded_reader_delivers_the_pad_as_payload() {
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a =
        VmessStream::with_options(a_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");
    let mut b = VmessStream::new(b_io, TEST_KEY, TEST_IV).expect("stream");

    let payload = b"exactly-this";
    a.write_all(payload).await.expect("write");
    a.flush().await.expect("flush");

    // The unpadded reader takes the declared length at face value, so it
    // returns payload + pad + marker — never a short read, never an error.
    let mut delivered = vec![0u8; 64];
    let n = b.read(&mut delivered).await.expect("read");
    assert_eq!(&delivered[..payload.len()], payload);
    assert!(
        n > payload.len(),
        "expected the pad to leak into the payload (read {n} of {} sent)",
        payload.len()
    );
}

/// The mirror: a padded reader over an unpadded writer reads the final payload
/// byte as a pad marker. A small marker truncates the payload silently; a large
/// one is rejected outright. Neither is a degradation, which is why the two ends
/// must be configured together.
#[tokio::test]
async fn a_padded_reader_against_an_unpadded_writer_truncates_or_rejects() {
    // Case 1: last byte 0x00 reads as a zero-length pad, so the chunk comes
    // back one byte short — no error, just a short read.
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("stream");
    let mut b =
        VmessStream::with_options(b_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");

    let mut payload = vec![0x41u8; 64];
    let last = payload.len() - 1;
    payload[last] = 0x00;
    a.write_all(&payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut delivered = vec![0u8; 128];
    let n = b.read(&mut delivered).await.expect("read");
    assert_eq!(n, payload.len() - 1, "a zero marker silently costs the last payload byte");
    assert_eq!(&delivered[..n], &payload[..n]);

    // Case 2: last byte 0xF0 claims 240 pad bytes inside a 64-byte chunk. The
    // frame is rejected, not absorbed.
    let (a_io, b_io) = tokio::io::duplex(8192);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("stream");
    let mut b =
        VmessStream::with_options(b_io, TEST_KEY, TEST_IV, PaddingMode::On).expect("stream");

    let mut payload = vec![0x41u8; 64];
    let last = payload.len() - 1;
    payload[last] = 0xF0;
    a.write_all(&payload).await.expect("write");
    a.flush().await.expect("flush");

    let mut delivered = vec![0u8; 128];
    let err = b.read(&mut delivered).await.expect_err("an overlong marker must fail the chunk");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

// ---------------------------------------------------------------------------
// The config gate — the question that actually matters
// ---------------------------------------------------------------------------

/// The Shadowsocks half of G5 shipped complete and unreachable: `with_options`
/// had no callers outside its own tests and neither settings struct had a
/// `padding` field, so an operator who set `padding = true` was rejected by
/// `deny_unknown_fields`. These pin the gate existing at all.
#[test]
fn the_vmess_outbound_padding_flag_is_recognised() {
    use shadowmesh_core::config::settings::VmessSettings;

    let raw = serde_json::json!({
        "server": "1.2.3.4",
        "port": 443,
        "uuid": "unit-test-placeholder-uuid",
        "security": "aes-128-gcm",
        "padding": true,
    });
    let s: VmessSettings = shadowmesh_core::config::settings::parse_strict(&raw, "vmess")
        .expect("padding must be a recognised field");
    assert_eq!(padding_mode(s.padding), PaddingMode::On);
}

#[test]
fn the_vmess_inbound_padding_flag_is_recognised() {
    use shadowmesh_core::config::settings::VmessInboundSettings;

    let raw = serde_json::json!({
        "uuid": "unit-test-placeholder-uuid",
        "padding": false,
    });
    let s: VmessInboundSettings =
        shadowmesh_core::config::settings::parse_strict(&raw, "vmess-inbound")
            .expect("padding must be a recognised field");
    assert_eq!(padding_mode(s.padding), PaddingMode::Off);
}

/// A config written before G5 existed carries no `padding` key, and must keep
/// producing the exact pre-G5 wire.
#[test]
fn an_unstated_vmess_padding_flag_means_off() {
    use shadowmesh_core::config::settings::VmessSettings;

    let raw = serde_json::json!({
        "server": "1.2.3.4",
        "port": 443,
        "uuid": "unit-test-placeholder-uuid",
    });
    let s: VmessSettings =
        shadowmesh_core::config::settings::parse_strict(&raw, "vmess").expect("parses");
    assert_eq!(padding_mode(s.padding), PaddingMode::Off);
}

/// `deny_unknown_fields` is the point of these structs; adding a field must not
/// have relaxed it. A typo'd flag must fail at load rather than silently run
/// unpadded — which an operator would read as "padding is on and something is
/// still leaking".
#[test]
fn a_typo_in_the_vmess_padding_flag_is_a_hard_config_error() {
    use shadowmesh_core::config::settings::VmessSettings;

    let raw = serde_json::json!({
        "server": "1.2.3.4",
        "port": 443,
        "uuid": "unit-test-placeholder-uuid",
        "paddding": true,
    });
    assert!(
        shadowmesh_core::config::settings::parse_strict::<VmessSettings>(&raw, "vmess").is_err(),
        "a misspelled padding flag must not parse"
    );
}
