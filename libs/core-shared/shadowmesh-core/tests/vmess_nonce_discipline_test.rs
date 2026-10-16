//! VMess AEAD nonce discipline: **one nonce per AEAD call, never per frame**.
//!
//! # The defect this is built around
//!
//! `VmessStream::poll_write` used to seal a frame's length chunk and its body
//! chunk with the **same** 96-bit AES-GCM nonce, advancing the counter once per
//! frame:
//!
//! ```text
//! let nonce_len     = next_nonce(write_seq);
//! let nonce_payload = next_nonce(write_seq);   // same value
//! write_seq += 1;
//! ```
//!
//! Reusing a GCM nonce under one key is not a hygiene issue. Per the GCM
//! construction, two ciphertexts sealed under the same nonce and key give an
//! equation in the GHASH authentication key `H`, and recovering `H` forges
//! authentic ciphertext for that session key. The reader mirrored the writer,
//! so every round-trip test in the tree stayed green — interop was the reason
//! the bug survived, not evidence against it.
//!
//! # Why a round-trip test cannot find this
//!
//! Every pre-existing VMess test asserts that a writer and a reader agree.
//! They did agree: both reused the nonce. A test that only round-trips passes
//! with the defect present and proves nothing about it. So the assertions here
//! are **not** "it still round-trips". They reach the wire, recover the nonce
//! each chunk was actually sealed under, and state the property directly:
//!
//! - `no_two_chunks_in_a_frame_share_a_nonce` — the decisive one. It opens a
//!   frame's body chunk under the *length chunk's* nonce and requires that to
//!   **fail**. With the defect present that open succeeds, because the body
//!   really was sealed under that nonce.
//! - `the_nonce_advances_once_per_aead_call` — pins the whole schedule: the
//!   `i`-th AEAD call on the wire uses nonce `i`. Nonces are unique, and
//!   contiguous, so a future "optimisation" that re-derives a nonce cannot
//!   reappear without failing here.
//! - `a_reader_rejects_a_frame_whose_two_chunks_share_a_nonce` — the read
//!   side. A hand-built frame carrying the old discipline is fed to the real
//!   reader and must be rejected. Without this, a fix applied to `poll_write`
//!   alone would desynchronise the reader and every round-trip test would fail
//!   while the security property stayed unverified.
//! - `writer_and_reader_stay_in_lockstep_over_many_frames` — the guard, not the
//!   proof. Both counters advance identically, so a long stream stays readable;
//!   this one passes with the defect present and is here only so the change
//!   cannot silently desynchronise the two halves.
//!
//! # On `nonce_for` being restated here
//!
//! The nonce derivation is reimplemented rather than exported. A wire walk
//! that reused `VmessStream::next_nonce` would agree with the implementation
//! by construction, which is precisely the failure mode this file exists to
//! rule out. The same reasoning applies to the two padding suites that walk
//! this wire independently.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use shadowmesh_core::transport::outbound::vmess::VmessStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Obvious placeholder, not a credential: these frames never leave the process.
const TEST_KEY: [u8; 16] = [0x5A; 16];
const TEST_IV: [u8; 16] = [0x17; 16];

const VMESS_TAG_SIZE: usize = 16;

/// Must match the reader's `MAX_VMESS_CHUNK`.
const MAX_VMESS_CHUNK: usize = 16384;

/// `VmessStream::next_nonce`, restated. See the module note on why.
fn nonce_for(seq: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

/// A separate opening key per call: `UnboundKey` is deliberately not `Clone`,
/// so sharing one would be a claim the library does not make.
fn opening() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &TEST_KEY).expect("test key is 16 bytes"))
}

fn sealing() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &TEST_KEY).expect("test key is 16 bytes"))
}

/// Drive the real writer and capture every byte it puts on the wire.
async fn capture_wire(frames: usize, payload: &[u8]) -> Vec<u8> {
    let (a_io, tap_io) = tokio::io::duplex(1 << 20);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("stream");

    let payload = payload.to_vec();
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
        match AsyncReadExt::read(&mut tap, &mut buf).await {
            Ok(0) => break,
            Ok(n) => wire.extend_from_slice(&buf[..n]),
            Err(e) => panic!("tap read: {e}"),
        }
    }
    writer.await.expect("writer");
    wire
}

/// One decrypted chunk: the AEAD call index it occupied and its plaintext.
struct Chunk {
    call_index: u64,
    plaintext: Vec<u8>,
    /// The chunk exactly as it appeared on the wire, tag included.
    sealed: Vec<u8>,
}

/// Walk the whole chunk stream, opening chunk `i` under nonce `i`.
///
/// This is the schedule assertion itself: if the walk completes, the `i`-th
/// AEAD call on the wire was sealed under nonce `i`, so no nonce was ever
/// reused and none was skipped.
fn walk_chunks(wire: &[u8], frames: usize) -> Vec<Chunk> {
    let opening = opening();
    let mut chunks = Vec::with_capacity(frames * 2);
    let mut cursor = 0usize;

    while chunks.len() < frames * 2 {
        let call_index = chunks.len() as u64;

        // `open_in_place` takes ciphertext *with* the tag appended, which is
        // what the stream itself does.
        let mut len_chunk = wire[cursor..cursor + 2 + VMESS_TAG_SIZE].to_vec();
        cursor += 2 + VMESS_TAG_SIZE;
        let opened = opening
            .open_in_place(nonce_for(call_index), Aad::empty(), &mut len_chunk)
            .unwrap_or_else(|_| panic!("AEAD call {call_index} (length chunk) must authenticate"));
        let frame_len = u16::from_be_bytes([opened[0], opened[1]]) as usize;
        assert!(frame_len <= MAX_VMESS_CHUNK, "chunk must stay inside the reader's bound");
        chunks.push(Chunk {
            call_index,
            plaintext: opened.to_vec(),
            sealed: wire[cursor - (2 + VMESS_TAG_SIZE)..cursor].to_vec(),
        });

        let mut body = wire[cursor..cursor + frame_len + VMESS_TAG_SIZE].to_vec();
        cursor += frame_len + VMESS_TAG_SIZE;
        let opened = opening
            .open_in_place(nonce_for(call_index + 1), Aad::empty(), &mut body)
            .unwrap_or_else(|_| {
                panic!("AEAD call {} (body chunk) must authenticate", call_index + 1)
            });
        chunks.push(Chunk {
            call_index: call_index + 1,
            plaintext: opened.to_vec(),
            sealed: wire[cursor - (frame_len + VMESS_TAG_SIZE)..cursor].to_vec(),
        });
    }
    chunks
}

// ---------------------------------------------------------------------------
// The decisive assertion
// ---------------------------------------------------------------------------

/// Within one frame, the length chunk's nonce must not open the body chunk.
///
/// Stated as a *negative* open rather than as a positive one on purpose: the
/// defect is that the body chunk really was sealed under the length chunk's
/// nonce, so the only way this test can fail is if the reuse is present.
#[tokio::test]
async fn no_two_chunks_in_a_frame_share_a_nonce() {
    let frames = 8usize;
    let payload = b"nonce-discipline";
    let wire = capture_wire(frames, payload).await;
    let chunks = walk_chunks(&wire, frames);

    let opening = opening();
    let mut frame = 0usize;
    while frame < frames {
        let len_chunk = &chunks[frame * 2];
        let body_chunk = &chunks[frame * 2 + 1];

        // The property, stated literally.
        assert_ne!(
            len_chunk.call_index, body_chunk.call_index,
            "frame {frame}: both chunks consumed one nonce"
        );

        // Both chunks opened on their own nonce above, so each recovered its
        // real plaintext. A body that did not would mean the walk decrypted
        // something it was never given.
        assert_eq!(
            body_chunk.plaintext, payload,
            "frame {frame}: body chunk must decrypt to the payload"
        );

        // ...and demonstrated: the body must not authenticate under the nonce
        // its own frame's length chunk used.
        let mut reused_input = body_chunk.sealed.clone();
        let reused =
            opening.open_in_place(nonce_for(len_chunk.call_index), Aad::empty(), &mut reused_input);
        assert!(
            reused.is_err(),
            "frame {frame}: the body chunk authenticates under the length chunk's nonce ({}) — \
             two AEAD chunks share one nonce, which leaks the GHASH key",
            len_chunk.call_index
        );
        frame += 1;
    }
}

/// The schedule itself: AEAD call `i` uses nonce `i`.
///
/// `walk_chunks` encodes this — it opens chunk `i` under nonce `i` and fails
/// otherwise — so the test body is the invariant restated as a count.
#[tokio::test]
async fn the_nonce_advances_once_per_aead_call() {
    let frames = 8usize;
    let payload = b"nonce-discipline";
    let wire = capture_wire(frames, payload).await;
    let chunks = walk_chunks(&wire, frames);

    assert_eq!(chunks.len(), frames * 2, "two AEAD calls per frame");
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.call_index, i as u64, "AEAD calls must be numbered in wire order");
        // Every length chunk declares this payload's length; every body chunk
        // carries it. Both were opened under nonce `i`, so the schedule walked
        // is the schedule actually used.
        let expected: &[u8] =
            if i % 2 == 0 { &[(payload.len() >> 8) as u8, payload.len() as u8] } else { payload };
        assert_eq!(
            chunk.plaintext, expected,
            "AEAD call {i} must recover its own plaintext, not another chunk's"
        );
    }

    // Every chunk must carry a nonce no other chunk used. The walk already
    // proved each one opens under its own index; this pins the count so a
    // writer that sealed under, say, a constant nonce could not pass by
    // walking zero chunks.
    let mut used: Vec<u64> = chunks.iter().map(|c| c.call_index).collect();
    used.sort_unstable();
    used.dedup();
    assert_eq!(used.len(), frames * 2, "every AEAD call must use a distinct nonce");
}

// ---------------------------------------------------------------------------
// The read side
// ---------------------------------------------------------------------------

/// The reader must not accept the old discipline.
///
/// The frame below is built by hand with both chunks sealed under nonce 0 —
/// the exact bytes a pre-fix writer produced. A reader that still mirrors the
/// reuse accepts it and delivers the payload; this asserts it does not.
#[tokio::test]
async fn a_reader_rejects_a_frame_whose_two_chunks_share_a_nonce() {
    let sealing = sealing();
    let payload = b"sealed-twice-under-one-nonce";

    // The historical writer: length chunk and body chunk, one shared nonce.
    let mut len_chunk = (payload.len() as u16).to_be_bytes().to_vec();
    let tag = sealing
        .seal_in_place_separate_tag(nonce_for(0), Aad::empty(), &mut len_chunk)
        .expect("seal length chunk");
    let mut body = payload.to_vec();
    let tag2 = sealing
        .seal_in_place_separate_tag(nonce_for(0), Aad::empty(), &mut body)
        .expect("seal body chunk");

    let mut wire = len_chunk;
    wire.extend_from_slice(tag.as_ref());
    wire.extend_from_slice(&body);
    wire.extend_from_slice(tag2.as_ref());

    let (mut tx, rx) = tokio::io::duplex(1 << 16);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);

    let mut reader = VmessStream::new(rx, TEST_KEY, TEST_IV).expect("reader");
    let mut got = vec![0u8; payload.len()];
    let err = reader
        .read_exact(&mut got)
        .await
        .expect_err("a frame whose two chunks share a nonce must be rejected");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "the reader must fail the frame, not absorb it"
    );
}

/// A frame built under the corrected discipline must be accepted, so the test
/// above is rejecting the reuse and not simply rejecting everything.
#[tokio::test]
async fn a_reader_accepts_a_frame_whose_two_chunks_use_distinct_nonces() {
    let sealing = sealing();
    let payload = b"sealed-once-per-nonce";

    let mut len_chunk = (payload.len() as u16).to_be_bytes().to_vec();
    let tag = sealing
        .seal_in_place_separate_tag(nonce_for(0), Aad::empty(), &mut len_chunk)
        .expect("seal length chunk");
    let mut body = payload.to_vec();
    let tag2 = sealing
        .seal_in_place_separate_tag(nonce_for(1), Aad::empty(), &mut body)
        .expect("seal body chunk");

    let mut wire = len_chunk;
    wire.extend_from_slice(tag.as_ref());
    wire.extend_from_slice(&body);
    wire.extend_from_slice(tag2.as_ref());

    let (mut tx, rx) = tokio::io::duplex(1 << 16);
    tx.write_all(&wire).await.expect("feed");
    drop(tx);

    let mut reader = VmessStream::new(rx, TEST_KEY, TEST_IV).expect("reader");
    let mut got = vec![0u8; payload.len()];
    reader.read_exact(&mut got).await.expect("distinct nonces must be readable");
    assert_eq!(got, payload);
}

// ---------------------------------------------------------------------------
// Lockstep guard
// ---------------------------------------------------------------------------

/// A long stream stays readable end to end.
///
/// This one passes with the nonce reuse present and proves nothing about it.
/// It is here so that advancing both counters identically cannot desynchronise
/// the writer from the reader: a one-sided fix would fail here.
#[tokio::test]
async fn writer_and_reader_stay_in_lockstep_over_many_frames() {
    let frames = 64usize;
    let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();

    let (a_io, b_io) = tokio::io::duplex(1 << 20);
    let mut a = VmessStream::new(a_io, TEST_KEY, TEST_IV).expect("writer");
    let mut b = VmessStream::new(b_io, TEST_KEY, TEST_IV).expect("reader");

    let expected_len = frames * payload.len();
    let per_frame = payload.clone();
    let writer = tokio::spawn(async move {
        for _ in 0..frames {
            a.write_all(&per_frame).await.expect("write");
        }
        a.flush().await.expect("flush");
    });

    let mut got = vec![0u8; expected_len];
    b.read_exact(&mut got).await.expect("every frame must be readable");
    writer.await.expect("writer");

    for f in 0..frames {
        assert_eq!(
            &got[f * payload.len()..(f + 1) * payload.len()],
            &payload[..],
            "frame {f} must survive unchanged"
        );
    }
}
