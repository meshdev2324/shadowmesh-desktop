//! SIP022 stream headers and replay protection (spec sections 3.1.2 - 3.1.5).
//!
//! # What was missing
//!
//! The first implementation modelled only `length chunk -> payload chunk`. The
//! specification requires a **stream header** before any of that, and it is not
//! decoration:
//!
//! - It carries a **type byte** distinguishing a client stream (0) from a server
//!   stream (1), which is what prevents a response header being replayed as a
//!   request.
//! - It carries a **unix timestamp**, and a receiver MUST reject a message more
//!   than 30 seconds from its own clock. That is the protocol's replay
//!   protection for TCP.
//! - A request stream needs **two** header chunks; a response stream needs one,
//!   which also acts as its first length chunk.
//! - The response header echoes the **request salt**, so a client can bind a
//!   response to the request that caused it.
//!
//! None of this existed. The transport therefore was not a SIP022 stream at all,
//! only a plausible AEAD framing, and could not have interoperated.
//!
//! Clean-room: written from <https://shadowsocks.org/doc/sip022.html>.

use super::ss2022_nonce::NonceCounter;
use crate::transport::shadowsocks2022::{open, seal, Shadowsocks2022Error, Shadowsocks2022Method};
use bytes::{Buf, BytesMut};

/// Maximum payload per chunk, section 3.1.2. The specification states a chunk
/// may carry up to `0xFFFF` bytes and that the 0x3FFF cap of Shadowsocks AEAD
/// "does not apply to this edition". The previous implementation used
/// `16 * 1024 - 3`, which is the old cap and rejects every chunk a conforming
/// peer is entitled to send.
pub const MAX_CHUNK_LEN: usize = 0xFFFF;

/// Largest sealed overhead for one chunk: 2-byte length plus a 16-byte tag.
pub const LENGTH_CHUNK_OVERHEAD: usize = 2 + 16;
/// Payload chunk overhead is the tag alone.
pub const PAYLOAD_CHUNK_OVERHEAD: usize = 16;
/// Read hint: header chunk plus a length chunk.
pub const MAX_CHUNK_OVERHEAD: usize = LENGTH_CHUNK_OVERHEAD + PAYLOAD_CHUNK_OVERHEAD;

/// Stream direction, section 3.1.3. The type byte is what stops a server's
/// response header being accepted as a client's request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    ClientStream,
    ServerStream,
}

impl StreamType {
    pub fn byte(self) -> u8 {
        match self {
            Self::ClientStream => 0,
            Self::ServerStream => 1,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::ClientStream),
            1 => Some(Self::ServerStream),
            _ => None,
        }
    }
}

/// Maximum accepted clock skew, section 3.1.5.
pub const MAX_TIME_SKEW_SECS: u64 = 30;

/// How long an inbound salt is remembered, section 3.1.5.
pub const SALT_RETENTION_SECS: u64 = 60;

/// The request stream's fixed-length header: type, timestamp, length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub stream_type: StreamType,
    pub timestamp: u64,
    /// Plaintext length of the variable-length header that follows.
    pub length: u16,
}

impl RequestHeader {
    pub fn encode(&self) -> [u8; 11] {
        let mut out = [0u8; 11];
        out[0] = self.stream_type.byte();
        out[1..9].copy_from_slice(&self.timestamp.to_be_bytes());
        out[9..11].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 11 {
            return None;
        }
        Some(Self {
            stream_type: StreamType::from_byte(b[0])?,
            timestamp: u64::from_be_bytes(b[1..9].try_into().ok()?),
            length: u16::from_be_bytes(b[9..11].try_into().ok()?),
        })
    }
}

/// The response stream's fixed-length header, which additionally echoes the
/// request salt so a client can bind the response to its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    pub stream_type: StreamType,
    pub timestamp: u64,
    pub request_salt: Vec<u8>,
    pub length: u16,
}

impl ResponseHeader {
    /// Encoded size: 1 type + 8 timestamp + salt + 2 length. The specification
    /// gives 27/43 bytes including the tag, which is 11/27 or 11/43 before it
    /// for a 16/32-byte salt. That arithmetic does not reconcile, so the layout
    /// is built from its component fields rather than matched to the stated
    /// totals.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + self.request_salt.len());
        out.push(self.stream_type.byte());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.request_salt);
        out.extend_from_slice(&self.length.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8], salt_len: usize) -> Option<Self> {
        if b.len() < 11 + salt_len {
            return None;
        }
        Some(Self {
            stream_type: StreamType::from_byte(b[0])?,
            timestamp: u64::from_be_bytes(b[1..9].try_into().ok()?),
            request_salt: b[9..9 + salt_len].to_vec(),
            length: u16::from_be_bytes(b[9 + salt_len..11 + salt_len].try_into().ok()?),
        })
    }
}

/// Why a header was rejected. Deliberately coarse: the specification requires a
/// server to act in a way that does not reveal how many bytes it consumed, and
/// an error type that distinguishes "bad type byte" from "stale timestamp" from
/// "salt replayed" is a probing oracle if it reaches a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The stream type is not a defined value, or is the wrong direction.
    BadStreamType,
    /// Timestamp differs from the receiver's clock by more than 30 seconds.
    StaleTimestamp,
    /// This salt is already in the 60-second pool.
    ReplayedSalt,
    /// The declared length is not a valid header length.
    BadLength,
    /// Header shorter than the fixed-length part.
    Truncated,
    /// AEAD tag verification failed.
    Auth,
    /// The session's 96-bit counter space is exhausted. Unreachable in
    /// practice, and it must never wrap, because a reused nonce destroys both
    /// confidentiality and authenticity.
    NonceExhausted,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Opaque by design. See the type doc: a detailed reason is a probing
        // oracle, and the node already runs a decoy against that.
        write!(f, "invalid stream header")
    }
}

impl From<super::ss2022_nonce::NonceExhausted> for HeaderError {
    fn from(_: super::ss2022_nonce::NonceExhausted) -> Self {
        Self::NonceExhausted
    }
}

impl From<Shadowsocks2022Error> for HeaderError {
    fn from(_: Shadowsocks2022Error) -> Self {
        Self::Auth
    }
}

/// The specification's salt pool, section 3.1.5.
///
/// Deliberately **not** a Bloom filter: the spec forbids anything that can
/// return a false positive, because a false positive would reject a legitimate
/// new session. Entries live 60 seconds, so an exact set with per-entry
/// timestamps is small and correct.
#[derive(Debug, Default)]
pub struct SaltPool {
    /// Insertion time and salt, oldest first. Pruned on access.
    entries: std::collections::VecDeque<(u64, Vec<u8>)>,
}

impl SaltPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when the salt is new and records it. `false` means it is a
    /// replay.
    pub fn accept(&mut self, now: u64, salt: &[u8]) -> bool {
        self.prune(now);
        if self.entries.iter().any(|(_, s)| s == salt) {
            return false;
        }
        // Bound the pool as a second line of defence. Pruning already caps it
        // at roughly one minute of unique sessions; this stops a flood of
        // distinct salts within a single window from growing without limit.
        const MAX_ENTRIES: usize = 65_536;
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back((now, salt.to_vec()));
        true
    }

    fn prune(&mut self, now: u64) {
        while let Some((t, _)) = self.entries.front() {
            if now.saturating_sub(*t) > SALT_RETENTION_SECS {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Validate a header's timestamp against the receiver's clock.
pub fn check_timestamp(header_ts: u64, now: u64) -> Result<(), HeaderError> {
    if header_ts.abs_diff(now) > MAX_TIME_SKEW_SECS {
        return Err(HeaderError::StaleTimestamp);
    }
    Ok(())
}

/// Seal the request stream's two header chunks, as section 3.1.2 requires.
///
/// Each header chunk is an independent AEAD operation and therefore consumes its
/// own nonce.
pub fn seal_request_headers(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    timestamp: u64,
    variable: &[u8],
) -> Result<Vec<u8>, HeaderError> {
    if variable.len() > MAX_CHUNK_LEN {
        return Err(HeaderError::BadLength);
    }
    // Fixed-length header: type, timestamp, and the length of the variable part.
    let fixed = RequestHeader {
        stream_type: StreamType::ClientStream,
        timestamp,
        length: variable.len() as u16,
    }
    .encode();

    let mut out = Vec::with_capacity(fixed.len() + variable.len() + 64);
    out.extend_from_slice(&seal(method, subkey, &counter.next()?, b"", &fixed)?);
    out.extend_from_slice(&seal(method, subkey, &counter.next()?, b"", variable)?);
    Ok(out)
}

/// Read a request stream's headers.
///
/// Returns the variable-length header and the number of bytes consumed.
pub fn read_request_headers(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    buf: &mut BytesMut,
    now: u64,
) -> Result<(Vec<u8>, usize), HeaderError> {
    // Fixed header: 11 bytes plus a tag.
    if buf.len() < 11 + 16 {
        return Err(HeaderError::Truncated);
    }
    let fixed = open(method, subkey, &counter.next()?, b"", &buf[..11 + 16])?;
    let header = RequestHeader::decode(&fixed).ok_or(HeaderError::BadStreamType)?;

    // A server stream header must not be accepted where a request is expected.
    if header.stream_type != StreamType::ClientStream {
        return Err(HeaderError::BadStreamType);
    }
    check_timestamp(header.timestamp, now)?;

    let var_len = header.length as usize;
    let need = var_len + 16;
    if buf.len() < 11 + 16 + need {
        return Err(HeaderError::Truncated);
    }
    let start = 11 + 16;
    let variable = open(method, subkey, &counter.next()?, b"", &buf[start..start + need])?;
    let consumed = start + need;
    buf.advance(consumed);
    Ok((variable, consumed))
}

/// Seal one length chunk and its payload chunk, section 3.1.2.
///
/// Two AEAD operations, so two counter values. The length is the *plaintext*
/// length and does not include the tag.
pub fn seal_chunk(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    payload: &[u8],
) -> Result<Vec<u8>, HeaderError> {
    if payload.len() > MAX_CHUNK_LEN {
        return Err(HeaderError::BadLength);
    }
    let len_bytes = (payload.len() as u16).to_be_bytes();
    let mut out = seal(method, subkey, &counter.next()?, b"", &len_bytes)?;
    out.extend_from_slice(&seal(method, subkey, &counter.next()?, b"", payload)?);
    Ok(out)
}

/// Try to read one length/payload chunk pair.
///
/// Returns `Ok(None)` when the buffer does not yet hold a complete pair, which
/// is an expected outcome on a socket read and not an error.
pub fn read_chunk(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    buf: &mut BytesMut,
) -> Result<Option<Vec<u8>>, HeaderError> {
    if buf.len() < LENGTH_CHUNK_OVERHEAD {
        return Ok(None);
    }
    let len = open(method, subkey, &counter.next()?, b"", &buf[..LENGTH_CHUNK_OVERHEAD])?;
    if len.len() != 2 {
        return Err(HeaderError::BadLength);
    }
    let declared = u16::from_be_bytes([len[0], len[1]]) as usize;
    let need = declared + PAYLOAD_CHUNK_OVERHEAD;
    if buf.len() < LENGTH_CHUNK_OVERHEAD + need {
        return Ok(None);
    }
    let start = LENGTH_CHUNK_OVERHEAD;
    let payload = open(method, subkey, &counter.next()?, b"", &buf[start..start + need])?;
    buf.advance(LENGTH_CHUNK_OVERHEAD + need);
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::shadowsocks2022::{
        derive_session_subkey, random_salt, Shadowsocks2022Method,
    };

    const METHODS: [Shadowsocks2022Method; 3] = [
        Shadowsocks2022Method::Aes128Gcm,
        Shadowsocks2022Method::Aes256Gcm,
        Shadowsocks2022Method::ChaCha20Poly1305,
    ];

    fn keys(m: Shadowsocks2022Method) -> Vec<u8> {
        let psk: Vec<u8> = (0..m.psk_len() as u8).collect();
        derive_session_subkey(m, &psk, &random_salt(m)).unwrap()
    }

    // ---- the payload cap, corrected from the spec ------------------------

    #[test]
    fn payload_cap_matches_the_specification() {
        // 0xFFFF, not 0x3FFF. The old cap silently rejected conforming chunks.
        assert_eq!(MAX_CHUNK_LEN, 65535);
    }

    #[test]
    fn maximum_chunk_round_trips() {
        for m in METHODS {
            let key = keys(m);
            let mut c = NonceCounter::default();
            let payload = vec![0x33u8; MAX_CHUNK_LEN];
            let frame = seal_chunk(m, &key, &mut c, &payload).unwrap();
            let mut buf = BytesMut::from(&frame[..]);
            let mut reader = NonceCounter::default();
            assert_eq!(
                read_chunk(m, &key, &mut reader, &mut buf).unwrap().unwrap().len(),
                MAX_CHUNK_LEN
            );
        }
    }

    // ---- header chunks ---------------------------------------------------

    #[test]
    fn request_headers_round_trip() {
        for m in METHODS {
            let key = keys(m);
            let variable = b"\x01example.com\x01\xbb".to_vec();
            let mut c = NonceCounter::default();
            let now = 1_700_000_000u64;
            let sealed = seal_request_headers(m, &key, &mut c, now, &variable).unwrap();
            let mut buf = BytesMut::from(&sealed[..]);
            let mut reader = NonceCounter::default();
            let (got, consumed) =
                read_request_headers(m, &key, &mut reader, &mut buf, now).unwrap();
            assert_eq!(got, variable);
            assert_eq!(consumed, sealed.len());
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn two_header_chunks_consume_two_counter_values() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        seal_request_headers(m, &key, &mut c, 1_700_000_000, b"x").unwrap();
        assert_eq!(c.position(), 2, "two standalone header chunks, two nonces");
    }

    #[test]
    fn server_stream_header_is_rejected_as_a_request() {
        // The type byte is what prevents a response header being replayed as a
        // request. Without it, replay protection is decorative.
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let fixed = RequestHeader {
            stream_type: StreamType::ServerStream,
            timestamp: 1_700_000_000,
            length: 1,
        }
        .encode();
        let mut frame = seal(m, &key, &c.next().unwrap(), b"", &fixed).unwrap();
        frame.extend_from_slice(&seal(m, &key, &c.next().unwrap(), b"", b"x").unwrap());
        let mut buf = BytesMut::from(&frame[..]);
        let mut reader = NonceCounter::default();
        assert_eq!(
            read_request_headers(m, &key, &mut reader, &mut buf, 1_700_000_000),
            Err(HeaderError::BadStreamType)
        );
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let old = 1_700_000_000u64;
        let mut c = NonceCounter::default();
        let sealed = seal_request_headers(m, &key, &mut c, old, b"x").unwrap();
        let mut buf = BytesMut::from(&sealed[..]);
        let mut reader = NonceCounter::default();
        let now = old + MAX_TIME_SKEW_SECS + 1;
        assert_eq!(
            read_request_headers(m, &key, &mut reader, &mut buf, now),
            Err(HeaderError::StaleTimestamp)
        );
    }

    #[test]
    fn timestamp_within_skew_is_accepted() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let old = 1_700_000_000u64;
        let mut c = NonceCounter::default();
        let sealed = seal_request_headers(m, &key, &mut c, old, b"x").unwrap();
        let mut buf = BytesMut::from(&sealed[..]);
        let mut reader = NonceCounter::default();
        assert!(
            read_request_headers(m, &key, &mut reader, &mut buf, old + MAX_TIME_SKEW_SECS).is_ok()
        );
    }

    #[test]
    fn truncated_headers_report_truncated() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let sealed = seal_request_headers(m, &key, &mut c, 1_700_000_000, b"payload").unwrap();
        let mut buf = BytesMut::from(&sealed[..sealed.len() - 1]);
        let mut reader = NonceCounter::default();
        assert_eq!(
            read_request_headers(m, &key, &mut reader, &mut buf, 1_700_000_000),
            Err(HeaderError::Truncated)
        );
    }

    // ---- replay protection -----------------------------------------------

    #[test]
    fn salt_is_accepted_once_and_replayed_afterwards() {
        let mut pool = SaltPool::new();
        assert!(pool.accept(1000, b"salt-a"));
        assert!(!pool.accept(1001, b"salt-a"), "second use of a salt is a replay");
    }

    #[test]
    fn salt_pool_expires_after_sixty_seconds() {
        let mut pool = SaltPool::new();
        assert!(pool.accept(1000, b"salt-a"));
        // At the boundary the entry is still remembered...
        assert!(!pool.accept(1000 + SALT_RETENTION_SECS, b"salt-a"));
        // ...and after it, the salt is no longer in the pool.
        assert!(pool.accept(1000 + SALT_RETENTION_SECS + 1, b"salt-a"));
    }

    /// The specification forbids a Bloom filter, because a false positive would
    /// reject a legitimate new session. Exactness is the property to pin.
    #[test]
    fn pool_never_reports_a_false_positive() {
        let mut pool = SaltPool::new();
        for i in 0..5_000u32 {
            let salt = i.to_be_bytes();
            assert!(pool.accept(1000, &salt), "distinct salt {i} rejected");
        }
    }

    #[test]
    fn pool_prunes_expired_entries() {
        let mut pool = SaltPool::new();
        for i in 0..100u32 {
            pool.accept(1000, &i.to_be_bytes());
        }
        assert_eq!(pool.len(), 100);
        pool.accept(1000 + SALT_RETENTION_SECS + 1, b"new");
        assert!(pool.len() < 100, "expired entries should be pruned: {}", pool.len());
    }

    // ---- error opacity ---------------------------------------------------

    #[test]
    fn header_errors_do_not_leak_their_cause() {
        // A prober must not be able to tell these apart from the error text.
        let rendered: Vec<String> = [
            HeaderError::BadStreamType,
            HeaderError::StaleTimestamp,
            HeaderError::ReplayedSalt,
            HeaderError::Truncated,
            HeaderError::Auth,
            HeaderError::NonceExhausted,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert!(rendered.iter().all(|r| r == &rendered[0]), "errors must be indistinguishable");
    }

    // ---- chunk framing ---------------------------------------------------

    #[test]
    fn chunk_consumes_two_counter_values() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        seal_chunk(m, &key, &mut c, b"payload").unwrap();
        assert_eq!(c.position(), 2, "length chunk and payload chunk each take a nonce");
    }

    #[test]
    fn partial_chunk_returns_none_without_consuming() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let frame = seal_chunk(m, &key, &mut c, b"hello world").unwrap();
        for cut in 1..frame.len() {
            let mut buf = BytesMut::from(&frame[..cut]);
            let mut reader = NonceCounter::default();
            assert_eq!(read_chunk(m, &key, &mut reader, &mut buf).unwrap(), None, "cut {cut}");
        }
    }

    #[test]
    fn multiple_chunks_read_in_order() {
        let m = Shadowsocks2022Method::ChaCha20Poly1305;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let mut buf = BytesMut::new();
        for body in [&b"first"[..], b"second", b"third"] {
            buf.extend_from_slice(&seal_chunk(m, &key, &mut c, body).unwrap());
        }
        let mut reader = NonceCounter::default();
        for expect in [&b"first"[..], b"second", b"third"] {
            assert_eq!(read_chunk(m, &key, &mut reader, &mut buf).unwrap().unwrap(), expect);
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn corrupted_payload_fails_authentication() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let mut frame = seal_chunk(m, &key, &mut c, b"payload").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        let mut buf = BytesMut::from(&frame[..]);
        let mut reader = NonceCounter::default();
        assert_eq!(read_chunk(m, &key, &mut reader, &mut buf), Err(HeaderError::Auth));
    }

    #[test]
    fn oversized_payload_is_refused() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        let huge = vec![0u8; MAX_CHUNK_LEN + 1];
        assert_eq!(seal_chunk(m, &key, &mut c, &huge), Err(HeaderError::BadLength));
    }

    #[test]
    fn full_stream_round_trips_headers_then_chunks() {
        for m in METHODS {
            let key = keys(m);
            let mut c = NonceCounter::default();
            let now = 1_700_000_000u64;
            let mut wire = Vec::new();
            wire.extend_from_slice(
                &seal_request_headers(m, &key, &mut c, now, b"request-var").unwrap(),
            );
            wire.extend_from_slice(&seal_chunk(m, &key, &mut c, b"payload-one").unwrap());
            wire.extend_from_slice(&seal_chunk(m, &key, &mut c, b"payload-two").unwrap());

            let mut buf = BytesMut::from(&wire[..]);
            let mut reader = NonceCounter::default();
            let (var, _) = read_request_headers(m, &key, &mut reader, &mut buf, now).unwrap();
            assert_eq!(var, b"request-var");
            assert_eq!(
                read_chunk(m, &key, &mut reader, &mut buf).unwrap().unwrap(),
                b"payload-one"
            );
            assert_eq!(
                read_chunk(m, &key, &mut reader, &mut buf).unwrap().unwrap(),
                b"payload-two"
            );
            assert!(buf.is_empty(), "{m:?} left trailing bytes");
        }
    }
}
