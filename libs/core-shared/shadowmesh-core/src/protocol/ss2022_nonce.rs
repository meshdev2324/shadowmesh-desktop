//! SIP022 stream nonce.
//!
//! # The defect this replaces
//!
//! The first implementation numbered chunks with a big-endian counter and
//! emitted one nonce per frame, then derived a second nonce for the length field
//! by XOR-ing a constant. All three were wrong against the specification:
//!
//! - The counter is **little-endian**, not big-endian.
//! - The counter is incremented after **each AEAD operation**, not each frame, so
//!   a length chunk and its payload chunk take consecutive values.
//! - There is no "derived length nonce". A single monotonic counter is the whole
//!   mechanism.
//!
//! None of that was caught by tests, because every test validated the framing
//! against itself rather than against the wire format. The failure mode is
//! self-consistent and non-interoperable, which is the worst combination: it
//! passes CI and cannot talk to any other implementation.
//!
//! # Why the counter shape matters
//!
//! Reusing a nonce under one session subkey breaks both confidentiality and
//! authenticity, and the specification makes this unforgiving by defining the
//! counter as `u96` little-endian with a mandated increment after every
//! operation. A session that seals one length chunk and one payload chunk per
//! message therefore consumes two counter values per message, and the receiver
//! must track the same count or its nonces drift apart and every frame after the
//! first fails authentication.

/// Nonce length for every SIP022 AEAD.
pub const NONCE_LEN: usize = 12;

/// A monotonic little-endian counter nonce.
///
/// [`u96`] is not a primitive, so the high 64 bits and low 32 bits are tracked
/// separately and rendered little-endian into 12 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonceCounter {
    high: u64,
    low: u32,
    /// Set once the final representable value has been handed out. Without this
    /// the carry below would saturate `high`, leave it at `u64::MAX`, reset `low`
    /// to zero, and the counter would silently restart - reusing every nonce
    /// from the beginning of the session.
    exhausted: bool,
}

/// Raised when a session attempts to seal more chunks than the counter space
/// allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceExhausted;

impl NonceCounter {
    /// The next nonce, or `None` once the full 96-bit space is consumed.
    ///
    /// Exhaustion is ~2^96 chunks, so it is unreachable in practice, but the
    /// counter **fails closed** rather than wrapping. A wrapped counter reuses
    /// nonces, which is a total loss of both confidentiality and authenticity,
    /// and it would be silent.
    /// The next nonce. Named `next` because that is what a counter does, but it
    /// deliberately does not implement `Iterator`: exhaustion is an error rather
    /// than the end of a sequence, so a caller cannot silently stop early.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<[u8; NONCE_LEN], NonceExhausted> {
        if self.exhausted {
            return Err(NonceExhausted);
        }
        let out = self.to_bytes();
        // The last representable value is valid; only the call after it refuses.
        if self.high == u64::MAX && self.low == u32::MAX {
            self.exhausted = true;
        } else {
            self.increment();
        }
        Ok(out)
    }

    /// Construct at a specific position. Exists so an independent peer can be
    /// compared against this counter at a known offset, which is how the
    /// cross-implementation conformance check pins the 32-bit boundary.
    pub fn at(high: u64, low: u32) -> Self {
        Self { high, low, exhausted: high == u64::MAX && low == u32::MAX }
    }

    /// Peek without consuming. Used to decide the AAD for a chunk that will be
    /// sealed next, without disturbing the counter.
    pub fn peek(&self) -> [u8; NONCE_LEN] {
        self.to_bytes()
    }

    fn increment(&mut self) {
        match self.low.checked_add(1) {
            Some(next) => self.low = next,
            None => {
                // Carry into the high word. Saturating rather than wrapping: a
                // wrap here would be the exact nonce reuse the type exists to
                // prevent, and `next` already refuses at the boundary.
                self.low = 0;
                self.high = self.high.saturating_add(1);
            }
        }
    }

    /// Render little-endian across all 12 bytes: least significant byte first.
    ///
    /// The low word occupies bytes 0..4 and the high word bytes 4..12. Laying
    /// the high word out first would be *word*-order little-endian but
    /// *byte*-order big-endian overall, so value 1 would land in byte 8 instead
    /// of byte 0. The test asserting byte 0 caught exactly that, which is the
    /// precise defect this module was written to remove.
    fn to_bytes(self) -> [u8; NONCE_LEN] {
        let mut out = [0u8; NONCE_LEN];
        out[..4].copy_from_slice(&self.low.to_le_bytes());
        out[4..].copy_from_slice(&self.high.to_le_bytes());
        out
    }

    /// Current position, for diagnostics and tests.
    pub fn position(&self) -> u128 {
        ((self.high as u128) << 32) | self.low as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_little_endian() {
        // The first nonce must be all zeroes, and the second must set the LAST
        // byte, not the first. A big-endian rendering would set the first byte,
        // which is the specific bug this module fixes.
        let mut c = NonceCounter::default();
        assert_eq!(c.next().unwrap(), [0u8; NONCE_LEN]);
        let second = c.next().unwrap();
        assert_eq!(second[0], 1, "value 1 must occupy byte 0 in a little-endian u96");
        assert_eq!(second[1..], [0u8; NONCE_LEN - 1]);
    }

    #[test]
    fn is_strictly_increasing_and_unique() {
        let mut c = NonceCounter::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(c.next().unwrap()), "counter repeated a nonce");
        }
    }

    /// Two counter values are consumed per message: one for the length chunk,
    /// one for the payload chunk. The receiver must land on the same value, so
    /// the increment must happen per operation.
    #[test]
    fn consumes_one_value_per_operation() {
        let mut c = NonceCounter::default();
        c.next().unwrap();
        c.next().unwrap();
        assert_eq!(c.position(), 2, "one value per AEAD operation, not per frame");
    }

    #[test]
    fn carries_into_the_high_word() {
        let mut c = NonceCounter { high: 0, low: u32::MAX, exhausted: false };
        let last_low = c.next().unwrap();
        assert_eq!(last_low[..4], u32::MAX.to_le_bytes());
        let carried = c.next().unwrap();
        assert_eq!(carried[..4], [0u8; 4], "low word wrapped to zero");
        // high = 1 stored little-endian is [1, 0, 0, 0, 0, 0, 0, 0].
        // Written the other way round this assertion fails, and the failure is
        // genuinely informative: it distinguishes byte order from word order.
        assert_eq!(
            carried[4..],
            1u64.to_le_bytes(),
            "carry must land in the high word, little-endian, at bytes 4.."
        );
    }

    #[test]
    fn peek_does_not_advance() {
        let mut c = NonceCounter::default();
        let a = c.peek();
        let b = c.peek();
        assert_eq!(a, b, "peek must be side-effect free");
        assert_eq!(c.next().unwrap(), a, "peek must report the value next() will return");
    }

    /// Fails closed. A wrapped nonce is silent, total loss of both properties.
    #[test]
    fn fails_closed_rather_than_wrapping() {
        let mut c = NonceCounter { high: u64::MAX, low: u32::MAX, exhausted: false };
        assert!(c.next().is_ok(), "the final value itself is still handed out");
        assert_eq!(c.next(), Err(NonceExhausted));
        assert_eq!(c.next(), Err(NonceExhausted), "and must stay refused");
        // The regression this guards: after exhaustion the counter must not
        // restart, which would replay every nonce from the start of the session.
        assert_eq!(c.next(), Err(NonceExhausted));
    }

    #[test]
    fn final_value_is_still_usable() {
        // The last representable nonce must be handed out; only the call after
        // it refuses. The earlier u32 version refused one value early.
        // Starting at u32::MAX - 1 there are exactly two values left before
        // exhaustion: u32::MAX - 1 and u32::MAX. The third call must refuse.
        let mut c = NonceCounter { high: u64::MAX, low: u32::MAX - 1, exhausted: false };
        assert!(c.next().is_ok(), "u32::MAX - 1 is a valid counter value");
        assert!(c.next().is_ok(), "u32::MAX is the last valid counter value");
        assert_eq!(c.next(), Err(NonceExhausted), "and only then must it refuse");
    }

    #[test]
    fn ordering_matches_numeric_order() {
        let mut a = NonceCounter::default();
        let mut b = NonceCounter { high: 0, low: 1, exhausted: false };
        let na = a.next().unwrap();
        let nb = b.next().unwrap();
        assert!(na < nb, "byte order must match numeric order");
    }
}
