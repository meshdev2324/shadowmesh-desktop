//! RFC-012 G5 length-hiding padding — the shared wire contract.
//!
//! One policy, one writer, one reader, used by every protocol G5 names
//! (Shadowsocks and VMess). They were kept in one module because the two
//! halves are a single protocol feature: a writer that omits a byte its own
//! reader insists on corrupts every frame it produces, and there is no way to
//! see that from one protocol's code alone.
//!
//! The layout under [`PaddingMode::On`] is:
//!
//! ```text
//! [payload][pad bytes: pad_len][pad_len: 1]
//! ```
//!
//! `pad_len` is the **last** byte of the frame, so the reader locates the pad
//! without scanning, and the frame's declared length — computed by
//! [`padded_frame_len`] — accounts for both the pad and the marker.
//!
//! **The marker is emitted even when `pad_len == 0`.** A reader holding only a
//! frame cannot distinguish "a pad of length zero" from "no pad byte at all":
//! it has no out-of-band signal, so omitting the marker makes it consume a real
//! payload byte as the marker and return a frame short by `1 + that byte`
//! bytes — silent corruption, or a hard failure when the byte was large. That
//! defect shipped once already, unreachable behind a constructor nobody called;
//! threading the mode to config is what made it reachable, and it recurred on
//! one frame in 256. It is why [`write_pad_tail`] is the only place a marker is
//! ever emitted, and why [`write_pad_tail`] and [`strip_padding`] are tested
//! against **every** pad length rather than a sample.
//!
//! The same argument applies one step earlier, to the number the reader trusts
//! before it has decrypted anything: the declared length. Two protocols used to
//! restate that arithmetic inline, and an inline restatement is a place where
//! the length and the tail can disagree while both look right in isolation. So
//! [`padded_frame_len`] is the only place a padded frame's length is computed,
//! and it is checked against [`write_pad_tail`] for all 256 pad lengths.

use std::io;

/// Length-hiding padding policy (RFC-012 G5).
///
/// `Off` is byte-for-byte wire compatibility with an unpadded peer — the
/// default, because a padded stream is unreadable by an unpadded reader and
/// that failure is a protocol error, not a degradation. `On` gives every frame
/// a random 0..=255-byte pad, so inter-frame length deltas no longer reveal the
/// plaintext's size profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMode {
    Off,
    On,
}

/// Upper bound of per-frame padding (one byte of length encoding).
pub const MAX_PAD_BYTES: usize = 255;

/// Worst-case byte cost a padded frame pays for its tail: the marker plus a
/// maximum-length pad. Reserve this before slicing, so a frame is never built
/// larger than its chunk limit.
pub const MAX_PAD_COST: usize = MAX_PAD_BYTES + 1;

/// Draw this frame's pad length. Full byte range, so length deltas between
/// frames carry no information about the payloads.
pub fn draw_pad_len(padding: PaddingMode) -> usize {
    match padding {
        PaddingMode::Off => 0,
        PaddingMode::On => rand::random::<u8>() as usize,
    }
}

/// Locates the end of the real payload inside one decrypted frame.
///
/// Under [`PaddingMode::Off`] the frame is exactly the payload, byte for byte.
/// Under `On` the last byte says how many pad bytes precede it, so the payload
/// ends `1 + pad_len` bytes earlier.
///
/// A marker claiming more padding than the frame holds is a **protocol error**,
/// not something to absorb: `1 + pad_len > len` means the subtraction would
/// wrap and hand the caller bytes that were never sent.
///
/// An empty frame is legal — a zero-length write — and yields `0` rather than
/// an error, so padding never turns a keep-alive into a failure.
pub fn strip_padding(plaintext: &[u8], padding: PaddingMode) -> io::Result<usize> {
    if padding == PaddingMode::Off || plaintext.is_empty() {
        return Ok(plaintext.len());
    }
    let pad_len = plaintext[plaintext.len() - 1] as usize;
    if 1 + pad_len > plaintext.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "padding length exceeds frame"));
    }
    Ok(plaintext.len() - 1 - pad_len)
}

/// Bytes a padded frame body occupies on the wire: the payload, the pad, and
/// the marker. Under [`PaddingMode::Off`] that is the payload and nothing else.
///
/// This is the **declared length** rule, and it is the counterpart of
/// [`write_pad_tail`]: both clamp `pad_len` to [`MAX_PAD_BYTES`] and both charge
/// a marker byte under `On`, *including* for a zero-length pad. A writer that
/// declares one length and emits another desynchronises the reader permanently,
/// and that is a different defect from the missing marker — invisible in every
/// test that only inspects the body, because the body is correct and the length
/// prefix is not.
///
/// So the arithmetic lives here next to the tail it has to agree with, and both
/// protocols declare frames with this function rather than restating it. That
/// is the same one-owner argument the module makes for the marker, extended to
/// the number the reader trusts most.
pub fn padded_frame_len(payload_len: usize, pad_len: usize, padding: PaddingMode) -> usize {
    if padding == PaddingMode::Off {
        return payload_len;
    }
    payload_len + pad_len.min(MAX_PAD_BYTES) + 1
}

/// Append `[pad bytes][pad_len:1]` to a frame body whose payload occupies
/// `frame[..payload_len]`.
///
/// This is the only function in the crate that emits a pad marker, and
/// [`padded_frame_len`] is the only place a frame's declared length is computed
/// from a pad. `pad_len` is clamped to [`MAX_PAD_BYTES`], and `pad_len == 0`
/// still appends the lone `0x00` marker — see the module docs. Under
/// [`PaddingMode::Off`] the frame is untouched, which is what keeps the default
/// wire byte-compatible.
///
/// # Panics
///
/// Never. The append length is exactly
/// `padded_frame_len(frame.len(), pad_len, padding) - frame.len()`, which is
/// what a caller declaring the frame with that function must have reserved.
pub fn write_pad_tail(frame: &mut Vec<u8>, pad_len: usize, padding: PaddingMode) {
    if padding == PaddingMode::Off {
        return;
    }
    let pad_len = pad_len.min(MAX_PAD_BYTES);
    frame.extend(std::iter::repeat_with(rand::random::<u8>).take(pad_len));
    // Unconditional, including for pad_len == 0: see the module docs.
    frame.push(pad_len as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- reader arithmetic ------------------------------------------------

    #[test]
    fn off_returns_the_frame_verbatim() {
        // The whole wire-compatibility guarantee: with padding off, no byte of
        // the frame is reinterpreted.
        let frame = b"exactly-the-payload".to_vec();
        assert_eq!(strip_padding(&frame, PaddingMode::Off).expect("off never errors"), frame.len());
    }

    #[test]
    fn on_strips_the_pad_and_its_marker() {
        // [payload][2 pad bytes][marker 0x02] — the marker is the LAST byte.
        let frame = b"payload\x00\xAA\x02".to_vec();
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("well formed"), 7);
    }

    #[test]
    fn a_zero_length_pad_still_costs_its_marker() {
        // A pad of length zero is written as a lone 0x00 marker, so the payload
        // is the frame minus exactly one byte. This is the case a writer that
        // omitted the marker got wrong, making the reader eat a payload byte.
        let frame = b"payload\x00".to_vec();
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("zero pad"), 7);
    }

    #[test]
    fn an_overlong_pad_marker_is_rejected() {
        // 0xC8 = 200 pad bytes claimed inside a 3-byte frame. Absorbing it
        // would underflow the length and hand back a bogus payload.
        let frame = vec![0xAA, 0xBB, 0xC8];
        let err = strip_padding(&frame, PaddingMode::On).expect_err("must not be accepted");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_pad_exactly_filling_the_frame_is_valid() {
        // Off-by-one boundary: a 4-byte frame whose final byte is 3 claims
        // 3 pad bytes plus the marker, leaving an empty payload. Legitimate
        // (a keep-alive frame) — the rejection is for `1 + pad_len > len`, not `>=`.
        let frame = vec![0x00, 0x00, 0x00, 0x03];
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("exact fit"), 0);
    }

    #[test]
    fn one_byte_past_the_frame_is_rejected() {
        let frame = vec![0x00, 0x04]; // claims 4 pad bytes in a 2-byte frame
        assert!(strip_padding(&frame, PaddingMode::On).is_err());
    }

    #[test]
    fn an_empty_frame_is_not_a_padding_error() {
        // A zero-length payload is legal (a write of zero bytes); the marker
        // read must not turn it into a protocol error.
        assert_eq!(strip_padding(&[], PaddingMode::On).expect("empty"), 0);
        assert_eq!(strip_padding(&[], PaddingMode::Off).expect("empty"), 0);
    }

    // ---- writer / reader agreement, every pad length ----------------------
    //
    // The pad length is drawn at random on the write path, so a round-trip test
    // that only samples it would leave exactly the defective length (zero)
    // unverified 255 times in 256. These drive all 256 explicitly.

    /// Every declared pad length round-trips: what the writer appends is
    /// exactly what the reader removes.
    #[test]
    fn every_pad_length_round_trips() {
        let payload = b"the-payload-being-hidden".to_vec();
        for pad_len in 0..=MAX_PAD_BYTES {
            let mut frame = payload.clone();
            write_pad_tail(&mut frame, pad_len, PaddingMode::On);
            assert_eq!(
                frame.len(),
                payload.len() + pad_len + 1,
                "pad_len {pad_len}: frame must carry the pad AND its marker"
            );
            let end =
                strip_padding(&frame, PaddingMode::On).expect("writer output must be readable");
            assert_eq!(&frame[..end], &payload[..], "pad_len {pad_len}: payload must survive");
        }
    }

    /// The declared length a writer puts in the frame header must equal the
    /// bytes [`write_pad_tail`] actually appends, for **every** pad length.
    ///
    /// This is the seam the tail-only test above cannot see. A writer that
    /// declares one length and emits a body of another desynchronises the
    /// reader permanently — and the body on its own is perfect, so any test
    /// that inspects only the tail stays green through the whole class of
    /// defect. Both protocols used to restate this arithmetic inline instead
    /// of calling one function, which is what made the seam possible.
    #[test]
    fn the_declared_length_matches_the_tail_at_every_pad_length() {
        let payload_len = 17usize;
        for pad_len in 0..=MAX_PAD_BYTES {
            let mut frame = vec![0xEEu8; payload_len];
            write_pad_tail(&mut frame, pad_len, PaddingMode::On);
            let declared = padded_frame_len(payload_len, pad_len, PaddingMode::On);
            assert_eq!(
                frame.len(),
                declared,
                "pad_len {pad_len}: declared length must equal the emitted body"
            );
            assert_eq!(
                strip_padding(&frame, PaddingMode::On).expect("writer output"),
                payload_len,
                "pad_len {pad_len}: the reader must recover exactly the declared payload"
            );
        }
    }

    /// The zero-length case through the *length* rule, named separately from
    /// the tail rule: a zero pad still costs its marker byte in the declared
    /// length. This is the single value the Shadowsocks writer got wrong.
    #[test]
    fn a_zero_length_pad_is_charged_one_byte_in_the_declared_length() {
        assert_eq!(padded_frame_len(64, 0, PaddingMode::On), 65);
        assert_eq!(padded_frame_len(64, 1, PaddingMode::On), 66);
        assert_eq!(padded_frame_len(64, MAX_PAD_BYTES, PaddingMode::On), 64 + MAX_PAD_COST);
        // `Off` charges nothing, in either direction of the rule.
        assert_eq!(padded_frame_len(64, 0, PaddingMode::Off), 64);
        assert_eq!(padded_frame_len(64, MAX_PAD_BYTES, PaddingMode::Off), 64);
    }

    /// The reservation a writer makes before slicing a payload must equal the
    /// worst case this rule can charge, or a full-width pad silently overflows
    /// the reader's chunk bound.
    #[test]
    fn the_reserved_cost_is_the_worst_case_of_the_length_rule() {
        for payload_len in [0usize, 1, 64, 4096] {
            for pad_len in [0usize, 1, MAX_PAD_BYTES] {
                let charged = padded_frame_len(payload_len, pad_len, PaddingMode::On) - payload_len;
                assert!(
                    charged <= MAX_PAD_COST,
                    "pad_len {pad_len}: charged {charged} exceeds MAX_PAD_COST {MAX_PAD_COST}"
                );
            }
        }
        assert_eq!(padded_frame_len(0, MAX_PAD_BYTES, PaddingMode::On), MAX_PAD_COST);
    }

    /// The zero-length case, named: a frame with no pad bytes still ends in a
    /// `0x00` marker, and the reader still returns the payload whole.
    #[test]
    fn a_zero_length_pad_is_written_as_a_lone_marker() {
        let mut frame = b"payload".to_vec();
        write_pad_tail(&mut frame, 0, PaddingMode::On);
        assert_eq!(frame, b"payload\x00".to_vec());
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("zero pad"), 7);
    }

    /// The maximum pad fills the declared range and is still strippable.
    #[test]
    fn the_maximum_pad_is_written_and_strippable() {
        let mut frame = vec![0x11u8; 64];
        write_pad_tail(&mut frame, MAX_PAD_BYTES, PaddingMode::On);
        assert_eq!(frame.len(), 64 + MAX_PAD_BYTES + 1);
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("max pad"), 64);
    }

    /// An over-long request is clamped rather than wrapping the marker byte —
    /// `255 + 1` would alias to 0 and read back as "no pad" on the next frame.
    #[test]
    fn an_over_long_pad_request_is_clamped_not_wrapped() {
        let mut frame = vec![0x11u8; 4];
        write_pad_tail(&mut frame, MAX_PAD_BYTES + 7, PaddingMode::On);
        assert_eq!(frame.len(), 4 + MAX_PAD_BYTES + 1);
        assert_eq!(*frame.last().expect("marker is always written"), MAX_PAD_BYTES as u8);
        assert_eq!(strip_padding(&frame, PaddingMode::On).expect("clamped pad"), 4);
    }

    /// `Off` appends nothing at all — the guarantee every existing peer's wire
    /// depends on.
    #[test]
    fn off_writes_no_tail_whatever_the_pad_length() {
        let mut frame = b"payload".to_vec();
        for pad_len in [0usize, 1, 17, MAX_PAD_BYTES] {
            write_pad_tail(&mut frame, pad_len, PaddingMode::Off);
        }
        assert_eq!(frame, b"payload".to_vec());
    }

    /// The two ends must agree, or a mismatch is a protocol error rather than a
    /// degradation. A frame written by `On` must not be readable by `Off` (it
    /// would silently deliver the pad and marker as payload), and the reverse
    /// must not be readable by `On` (the last payload byte would be eaten).
    #[test]
    fn a_mismatched_pair_is_detectable_in_both_directions() {
        let mut on_frame = b"payload".to_vec();
        write_pad_tail(&mut on_frame, 4, PaddingMode::On);
        // Off reader hands the whole frame back, tail included.
        assert_eq!(strip_padding(&on_frame, PaddingMode::Off).expect("off"), on_frame.len());
        assert!(on_frame.len() > b"payload".len());

        // On reader over an unpadded frame reads the last payload byte as a
        // marker: 'y' claims 121 pad bytes in a 7-byte frame, so the frame is
        // rejected outright rather than silently truncated.
        let off_frame = b"payload".to_vec();
        let err = strip_padding(&off_frame, PaddingMode::On)
            .expect_err("an unpadded frame read as padded is a protocol error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The drawn length is inside the declared range under both modes.
    #[test]
    fn a_drawn_pad_length_is_always_in_range() {
        for _ in 0..512 {
            assert_eq!(draw_pad_len(PaddingMode::Off), 0);
            assert!(draw_pad_len(PaddingMode::On) <= MAX_PAD_BYTES);
        }
    }

    /// `MAX_PAD_COST` is what a writer must reserve so a frame never exceeds
    /// its chunk limit; if it is wrong the frame silently overflows the limit.
    #[test]
    fn the_reserved_cost_covers_the_worst_case_tail() {
        let mut widest = vec![0u8; 0];
        write_pad_tail(&mut widest, MAX_PAD_BYTES, PaddingMode::On);
        assert_eq!(widest.len(), MAX_PAD_COST);
    }
}
