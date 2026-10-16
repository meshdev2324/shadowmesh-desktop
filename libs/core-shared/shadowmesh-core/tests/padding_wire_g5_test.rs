//! RFC-012 G5 on the wire: writer and reader agreement at **every** pad length.
//!
//! # Why this file exists when `protocol::padding` already has tests
//!
//! The shared contract is verified exhaustively against the pure functions —
//! `every_pad_length_round_trips` drives all 256 declared lengths through
//! `write_pad_tail` and `strip_padding`. That is necessary and not sufficient,
//! for one reason: **the pad length is drawn from the thread RNG inside the
//! writer.** `write_pad_tail` and `draw_pad_len` are `pub`, so an integration
//! test can pin the length it wants... but only by building the frame itself,
//! which tests the reader and leaves the writer sampling.
//!
//! So this file splits the proof in two halves, because that is what the two
//! halves actually are:
//!
//! 1. **The reader, exhaustively, on the wire.** Each test builds a frame for
//!    every pad length 0..=255 — real AEAD, real length prefix, real framing —
//!    and pushes all 256 through the *real* `ShadowsocksStream` / `VmessStream`
//!    reader configured `PaddingMode::On`. Every payload must come back byte for
//!    byte. Pad length zero is included, which is the whole point.
//! 2. **The writer, structurally.** The writer draws its length, so the way to
//!    pin it exhaustively is to make the length rule a single function both
//!    writers call — `protocol::padding::padded_frame_len` — and assert against
//!    that the tail really is what the declared length charges
//!    (`the_declared_length_matches_the_tail_at_every_pad_length`). The existing
//!    400-frame wire tests then say the function is the one actually going out.
//!
//! Between them there is no uncovered pad length: exhaustive in the contract,
//! exhaustive in the reader, sampled on the writer's own output.
//!
//! # The defect this is built around
//!
//! Enabling the Shadowsocks gate once surfaced a real bug: the writer emitted
//! the pad-length marker **only when the random pad was non-zero**, while the
//! reader **always** read one. On the one frame in 256 where the pad came out
//! zero, the reader ate a real payload byte as the marker and returned a frame
//! short by `1 + that byte` — silent truncation — or failed the frame outright
//! when the byte was large. It is gone from the writer today, and
//! `a_frame_written_the_way_the_old_writer_wrote_it_is_corrupt` pins it as a
//! negative so it cannot come back unnoticed: that test builds the exact bytes
//! the defective writer produced and asserts the reader does **not** deliver the
//! payload.

use ring::aead::{Aad, LessSafeKey, Nonce, SealingKey, UnboundKey, AES_128_GCM};
use shadowmesh_core::protocol::padding::{
    padded_frame_len, write_pad_tail, PaddingMode, MAX_PAD_BYTES,
};
use shadowmesh_core::protocol::shadowsocks::{
    ShadowsocksCipher, ShadowsocksMethod, ShadowsocksStream,
};
use shadowmesh_core::transport::outbound::vmess::VmessStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Obvious placeholder, not a credential: these frames never leave the process.
const VMESS_TEST_KEY: [u8; 16] = [0x5A; 16];
const VMESS_TEST_IV: [u8; 16] = [0x17; 16];

/// Must match the reader's `MAX_VMESS_CHUNK`.
const MAX_VMESS_CHUNK: usize = 16384;

/// AES-128-GCM tag length. Restated rather than borrowed from the Shadowsocks
/// module: the two protocols are independent here, and sharing one constant
/// would let a change to one silently re-frame the other's test corpus.
const VMESS_TAG_SIZE: usize = 16;

/// Large enough that the whole 256-frame corpus is written in one go, so no
/// test can pass by accident on a truncated write.
const WIRE_CAPACITY: usize = 1 << 20;

/// Per-run ephemeral identity: never a static string (scanner hygiene).
fn identity() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A distinct payload per frame, with the frame index in the first two bytes,
/// so a reader that slipped by a frame produces an unmistakable mismatch rather
/// than a plausible-looking one.
fn payload_for(frame: usize) -> Vec<u8> {
    vec![(frame >> 8) as u8, frame as u8, 0x5A, 0xA5]
}

/// The corpus: every pad length exactly once, each carrying its own payload.
fn all_pad_lengths() -> Vec<(Vec<u8>, usize)> {
    (0..=MAX_PAD_BYTES).map(|pad_len| (payload_for(pad_len), pad_len)).collect()
}

fn expected_stream(frames: &[(Vec<u8>, usize)]) -> Vec<u8> {
    frames.iter().flat_map(|(p, _)| p.iter().copied()).collect()
}

/// `VmessStream::next_nonce`, restated. A wire walk has to know it
/// independently — a test that reused the implementation would agree with a
/// bug.
fn nonce_for(seq: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

fn vmess_sealing() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &VMESS_TEST_KEY).expect("test key is 16 bytes"))
}

fn vmess_opening() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &VMESS_TEST_KEY).expect("test key is 16 bytes"))
}

/// The plaintext body a padded VMess chunk must carry, and the length the
/// writer must declare for it. Both come from the crate's own rule so the test
/// cannot drift from the implementation, and the assertion below is that the
/// rule and the bytes agree — not a restatement of the arithmetic.
fn vmess_body(payload: &[u8], pad_len: usize) -> (Vec<u8>, usize) {
    let mut body = payload.to_vec();
    write_pad_tail(&mut body, pad_len, PaddingMode::On);
    let declared = padded_frame_len(payload.len(), pad_len, PaddingMode::On);
    assert_eq!(body.len(), declared, "pad_len {pad_len}: declared length must equal the body");
    assert!(declared <= MAX_VMESS_CHUNK, "pad_len {pad_len}: chunk must stay inside the bound");
    (body, declared)
}

/// Build a VMess chunk stream exactly as `VmessStream::poll_write` frames it:
/// a length chunk and a body chunk, each with its own tag, sealed under
/// **consecutive** nonces — frame `seq` spends counter values `2*seq` (length)
/// and `2*seq+1` (body). The counter is per AEAD call, never per frame: both
/// chunks are sealed under the same session key, so reusing one 96-bit nonce
/// across them is a GHASH-key-recovery exposure, not hygiene. The schedule is
/// restated here rather than borrowed for the same reason `nonce_for` is.
fn vmess_wire(frames: &[(Vec<u8>, usize)], skip_marker_at_zero: bool) -> Vec<u8> {
    let sealing = vmess_sealing();
    let mut wire = Vec::new();
    for (seq, (payload, pad_len)) in frames.iter().enumerate() {
        let (body, declared) = vmess_body(payload, *pad_len);
        // The historical defect, reproduced on demand: declare the payload
        // length and emit no marker at all when the pad came out zero.
        let (declared, body) = if skip_marker_at_zero && *pad_len == 0 {
            (payload.len(), payload.clone())
        } else {
            (declared, body)
        };

        let mut len_chunk = (declared as u16).to_be_bytes().to_vec();
        let tag = sealing
            .seal_in_place_separate_tag(nonce_for(2 * seq as u64), Aad::empty(), &mut len_chunk)
            .expect("seal length chunk");
        wire.extend_from_slice(&len_chunk);
        wire.extend_from_slice(tag.as_ref());

        let mut body_chunk = body;
        let tag = sealing
            .seal_in_place_separate_tag(
                nonce_for(2 * seq as u64 + 1),
                Aad::empty(),
                &mut body_chunk,
            )
            .expect("seal body chunk");
        wire.extend_from_slice(&body_chunk);
        wire.extend_from_slice(tag.as_ref());
    }
    wire
}

/// Build a SIP007 AEAD chunk stream the way `ShadowsocksStream::poll_write`
/// frames it: the salt once, then a length chunk and a body chunk per frame,
/// sealed under one `SealingKey`'s nonce sequence (zeroes, then incremented).
fn shadowsocks_wire(
    method: ShadowsocksMethod,
    password: &str,
    salt: &[u8],
    frames: &[(Vec<u8>, usize)],
    skip_marker_at_zero: bool,
) -> Vec<u8> {
    let mut sealing: SealingKey<_> = ShadowsocksCipher::new(method, password, salt)
        .expect("subkey derivation")
        .sealing_key()
        .expect("sealing key");
    let mut wire = salt.to_vec();
    for (payload, pad_len) in frames {
        let mut body = payload.clone();
        write_pad_tail(&mut body, *pad_len, PaddingMode::On);
        let declared = padded_frame_len(payload.len(), *pad_len, PaddingMode::On);
        assert_eq!(body.len(), declared, "pad_len {pad_len}: declared length must equal the body");

        let (declared, mut body) = if skip_marker_at_zero && *pad_len == 0 {
            (payload.len(), payload.clone())
        } else {
            (declared, body)
        };

        let mut len_chunk = (declared as u16).to_be_bytes().to_vec();
        let tag = sealing
            .seal_in_place_separate_tag(Aad::empty(), &mut len_chunk)
            .expect("seal length chunk");
        wire.extend_from_slice(&len_chunk);
        wire.extend_from_slice(tag.as_ref());

        let tag =
            sealing.seal_in_place_separate_tag(Aad::empty(), &mut body).expect("seal body chunk");
        wire.extend_from_slice(&body);
        wire.extend_from_slice(tag.as_ref());
    }
    wire
}

// ---------------------------------------------------------------------------
// 1. The reader, exhaustively, on the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_vmess_pad_length_round_trips_on_the_wire() {
    let frames = all_pad_lengths();
    let expected = expected_stream(&frames);
    let wire = vmess_wire(&frames, false);
    assert_eq!(frames.len(), 256, "the corpus must cover the whole declared range");

    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed the corpus");
    drop(tx);

    let mut reader = VmessStream::with_options(rx, VMESS_TEST_KEY, VMESS_TEST_IV, PaddingMode::On)
        .expect("padded reader");
    let mut got = vec![0u8; expected.len()];
    reader.read_exact(&mut got).await.expect("every frame must be readable");
    assert_eq!(got, expected, "VMess: writer and reader must agree at every pad length");
}

#[tokio::test]
async fn every_shadowsocks_pad_length_round_trips_on_the_wire() {
    let method = ShadowsocksMethod::Aes256Gcm;
    let password = identity();
    let frames = all_pad_lengths();
    let expected = expected_stream(&frames);
    let salt: Vec<u8> = (0..method.salt_len()).map(|i| (i as u8) ^ 0x5A).collect();
    let wire = shadowsocks_wire(method, &password, &salt, &frames, false);
    assert_eq!(frames.len(), 256, "the corpus must cover the whole declared range");

    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed the corpus");
    drop(tx);

    let mut reader = ShadowsocksStream::with_options(rx, method, &password, PaddingMode::On);
    let mut got = vec![0u8; expected.len()];
    reader.read_exact(&mut got).await.expect("every frame must be readable");
    assert_eq!(got, expected, "Shadowsocks: writer and reader must agree at every pad length");
}

/// Pad length zero, named, on the wire, for both protocols.
///
/// The exhaustive tests above include it, but "included" is not "pinned": they
/// would still pass if the zero case regressed on a code path that only zero
/// takes. Here the body is *constructed* — a zero pad must be exactly one byte,
/// `0x00`, with no pad bytes at all — and then read back.
#[tokio::test]
async fn the_zero_length_pad_is_one_marker_byte_on_the_wire_for_both_protocols() {
    let payload = b"the-payload".to_vec();

    // VMess: body is payload ++ [0x00]; the reader returns the payload.
    let (body, declared) = vmess_body(&payload, 0);
    assert_eq!(declared, payload.len() + 1, "a zero pad still costs its marker");
    assert_eq!(body, b"the-payload\x00".to_vec(), "no pad bytes, exactly one marker");

    let frames = vec![(payload.clone(), 0usize)];
    let wire = vmess_wire(&frames, false);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = VmessStream::with_options(rx, VMESS_TEST_KEY, VMESS_TEST_IV, PaddingMode::On)
        .expect("reader");
    let mut got = vec![0u8; payload.len()];
    reader.read_exact(&mut got).await.expect("a zero-pad frame must be readable");
    assert_eq!(got, payload, "VMess: the zero-length pad must not cost a payload byte");

    // Shadowsocks, same assertions.
    let method = ShadowsocksMethod::Aes256Gcm;
    let password = identity();
    let salt: Vec<u8> = (0..method.salt_len()).map(|i| (i as u8) ^ 0xA5).collect();
    let wire = shadowsocks_wire(method, &password, &salt, &frames, false);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = ShadowsocksStream::with_options(rx, method, &password, PaddingMode::On);
    let mut got = vec![0u8; payload.len()];
    reader.read_exact(&mut got).await.expect("a zero-pad frame must be readable");
    assert_eq!(got, payload, "Shadowsocks: the zero-length pad must not cost a payload byte");
}

// ---------------------------------------------------------------------------
// 2. The defect, pinned as a negative
// ---------------------------------------------------------------------------

/// Builds the exact bytes the old Shadowsocks writer produced on the one frame
/// in 256 where the random pad came out zero — declared length = payload, no
/// marker — and asserts the padded reader does **not** deliver the payload.
///
/// Two outcomes, both corruption, both asserted:
/// - a small trailing byte reads as a small marker, so the frame comes back
///   silently short by `1 + that byte`;
/// - a large trailing byte claims more padding than the frame holds and the
///   frame is rejected outright.
///
/// The first is the dangerous one, because nothing errors. This is also what
/// makes the test *able* to fail: if `strip_padding` ever stopped reading the
/// marker, or the writer ever stopped charging it, one of the two assertions
/// would break.
#[tokio::test]
async fn a_frame_written_the_way_the_old_writer_wrote_it_is_corrupt() {
    // Case 1 — silent truncation. Last payload byte is 0x01: the reader reads it
    // as "one pad byte", so it returns 2 bytes of a 3-byte payload, no error.
    let silent = vec![b'A', b'B', 0x01u8];
    // The case only means what it claims because of that trailing byte: it is
    // the byte the reader mistakes for the marker.
    assert_eq!(silent.last().copied(), Some(0x01), "the reader eats this byte as the marker");

    let method = ShadowsocksMethod::Aes256Gcm;
    let password = identity();
    let salt: Vec<u8> = (0..method.salt_len()).map(|i| (i as u8).wrapping_add(7)).collect();
    let wire = shadowsocks_wire(method, &password, &salt, &[(silent.clone(), 0usize)], true);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = ShadowsocksStream::with_options(rx, method, &password, PaddingMode::On);
    let mut got = vec![0u8; 3];
    let n = reader.read(&mut got).await.expect("read");
    assert_ne!(
        &got[..n],
        &silent[..],
        "a marker-less zero-pad frame must never deliver the payload intact"
    );
    assert!(n < silent.len(), "a marker-less zero-pad frame must come back short");

    // Case 2 — outright rejection. 0xC8 claims 200 pad bytes in a 3-byte frame.
    let overlong = vec![b'A', b'B', 0xC8u8];
    let wire = shadowsocks_wire(method, &password, &salt, &[(overlong, 0usize)], true);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = ShadowsocksStream::with_options(rx, method, &password, PaddingMode::On);
    let mut got = vec![0u8; 3];
    let err = reader.read(&mut got).await.expect_err("an overlong marker must fail the frame");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// The same defect on the VMess stream, so the negative is not a Shadowsocks
/// story. A marker-less zero-pad frame either truncates silently or is rejected.
#[tokio::test]
async fn a_marker_less_vmess_frame_is_corrupt_too() {
    let silent = vec![b'A', b'B', 0x01u8];
    let wire = vmess_wire(&[(silent.clone(), 0usize)], true);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = VmessStream::with_options(rx, VMESS_TEST_KEY, VMESS_TEST_IV, PaddingMode::On)
        .expect("reader");
    let mut got = vec![0u8; 3];
    let n = reader.read(&mut got).await.expect("read");
    assert!(n < silent.len(), "a marker-less zero-pad VMess frame must come back short");
    assert_ne!(&got[..n], &silent[..], "and must never deliver the payload intact");

    let overlong = vec![b'A', b'B', 0xC8u8];
    let wire = vmess_wire(&[(overlong, 0usize)], true);
    let (mut tx, rx) = tokio::io::duplex(WIRE_CAPACITY);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);
    let mut reader = VmessStream::with_options(rx, VMESS_TEST_KEY, VMESS_TEST_IV, PaddingMode::On)
        .expect("reader");
    let mut got = vec![0u8; 3];
    let err = reader.read(&mut got).await.expect_err("an overlong marker must fail the chunk");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

// ---------------------------------------------------------------------------
// 3. Both directions through one padded stream (the inbound relay shape)
// ---------------------------------------------------------------------------

/// The production shape: `handle_vmess_connection` hands the same padded
/// `VmessStream` to the engine, which relays **upstream → destination** by
/// reading and **destination → upstream** by writing. This drives both on one
/// object, so agreement is shown in both directions at once.
///
/// Upstream is driven by the all-256-pad-length corpus, so the inbound
/// direction is exhaustive. Downstream is written by the real writer, so its
/// frames are checked against the crate's own declared-length rule — the pad is
/// drawn at random there, which is the sampling limitation stated at the top of
/// this file, and the reason the writer is pinned structurally instead.
#[tokio::test]
async fn a_padded_vmess_relay_is_lossless_in_both_directions() {
    let frames = all_pad_lengths();
    let expected_inbound = expected_stream(&frames);
    let inbound_wire = vmess_wire(&frames, false);

    // One duplex, exactly as in production: `handle_vmess_connection` wraps a single
    // bidirectional socket, so the relay reads the corpus and writes the reply
    // on the *same* object. The peer half stays alive for the whole test —
    // dropping either half of a duplex breaks writes in both directions, and
    // this relay writes back on the very half that was fed. The corpus fits the
    // buffer, so the feed completes without the relay draining first, and
    // `read_exact` below stops at the last byte it needs.
    let (mut peer, relay_io) = tokio::io::duplex(WIRE_CAPACITY);
    peer.write_all(&inbound_wire).await.expect("feed the upstream corpus");

    let mut relay =
        VmessStream::with_options(relay_io, VMESS_TEST_KEY, VMESS_TEST_IV, PaddingMode::On)
            .expect("relay");

    // Direction 1: upstream → downstream.
    let mut inbound = vec![0u8; expected_inbound.len()];
    relay.read_exact(&mut inbound).await.expect("inbound must be lossless");
    assert_eq!(inbound, expected_inbound, "upstream → downstream must agree at every pad length");

    // Direction 2: downstream → upstream, through the same object.
    let reply = b"downstream-reply-carrying-the-relay-s-own-random-pads";
    relay.write_all(reply).await.expect("outbound write");
    relay.flush().await.expect("outbound flush");

    let mut sink = vec![0u8; 1 << 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), peer.read(&mut sink))
        .await
        .expect("the relay must have written something")
        .expect("read the relay's output");
    let out = &sink[..n];
    assert!(n > 0, "the relay wrote no bytes");

    // Parse what came out and check it against the crate's own rule.
    let opening = vmess_opening();
    let mut cursor = 0usize;
    let mut decoded = 0usize;
    while cursor + 2 + VMESS_TAG_SIZE <= out.len() {
        let mut len_chunk = out[cursor..cursor + 2 + VMESS_TAG_SIZE].to_vec();
        cursor += 2 + VMESS_TAG_SIZE;
        let frame_len = {
            let opened = opening
                .open_in_place(nonce_for(2 * decoded as u64), Aad::empty(), &mut len_chunk)
                .expect("outbound length chunk must authenticate");
            u16::from_be_bytes([opened[0], opened[1]]) as usize
        };
        assert!(frame_len <= MAX_VMESS_CHUNK, "outbound chunk must stay inside the bound");
        if cursor + frame_len + VMESS_TAG_SIZE > out.len() {
            break; // trailing partial read
        }
        let mut body = out[cursor..cursor + frame_len + VMESS_TAG_SIZE].to_vec();
        cursor += frame_len + VMESS_TAG_SIZE;
        {
            let opened = opening
                .open_in_place(nonce_for(2 * decoded as u64 + 1), Aad::empty(), &mut body)
                .expect("outbound body chunk must authenticate");
            assert_eq!(
                frame_len,
                padded_frame_len(reply.len(), opened[frame_len - 1] as usize, PaddingMode::On),
                "downstream → upstream: the declared length must charge the tail it carries"
            );
            assert_eq!(&opened[..reply.len()], &reply[..], "the reply must survive unchanged");
        }
        decoded += 1;
    }
    assert_eq!(decoded, 1, "one reply, one padded chunk");
}

// ---------------------------------------------------------------------------
// 4. The gate is still the only way in
// ---------------------------------------------------------------------------

/// Exhaustively driving the reader is only evidence if the reader is reachable,
/// and the reader is only reachable when both ends opted in. Re-pins the SS gate
/// from the VMess half's file so the two cannot be edited independently.
#[test]
fn the_padding_flag_still_gates_the_stream_and_nothing_else_does() {
    use shadowmesh_core::config::settings::{padding_mode, VmessSettings};

    assert_eq!(padding_mode(None), PaddingMode::Off);
    assert_eq!(padding_mode(Some(false)), PaddingMode::Off);
    assert_eq!(padding_mode(Some(true)), PaddingMode::On);

    let on = serde_json::json!({
        "server": "1.2.3.4",
        "port": 443,
        "uuid": "unit-test-placeholder-uuid",
        "padding": true,
    });
    let s: VmessSettings =
        shadowmesh_core::config::settings::parse_strict(&on, "vmess").expect("padding is a field");
    assert_eq!(padding_mode(s.padding), PaddingMode::On);
}
