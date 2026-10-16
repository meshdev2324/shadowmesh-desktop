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

/// The longest SOCKS5 address the variable-length header can carry: a domain
/// address is `ATYP(1) | length(1) | domain(255) | port(2)`, and IPv6 is
/// shorter. Every bound on the request header burst is computed from this, so it
/// is stated once and referenced rather than re-derived at each use site.
pub const MAX_SOCKS5_ADDR_LEN: usize = 1 + 1 + 255 + 2;

/// Section 3.1.3: `MaxPaddingLength = 9000` (`MinPaddingLength = 0`).
///
/// This is the *ceiling a reader must enforce*, and it is a different thing from
/// [`REQUEST_PADDING_MAX_BYTES`] below, which is the *length this writer draws*.
/// Conflating them is how a peer ends up accepting a 9000-byte pad while
/// intending something else entirely.
pub const MAX_PADDING_LENGTH: usize = 9000;

/// This project's policy for how much padding a request writer draws:
/// uniform over `1..=REQUEST_PADDING_MAX_BYTES`.
///
/// Section 3.1.4 requires that "either initial payload or padding MUST be
/// present", and permits a padding length anywhere in `1..=9000`. It also
/// requires, in the same section, that "the random salt and header chunks MUST
/// be buffered and sent in one write call to the underlying socket", because
/// "separate writes can result in predictable packet sizes, which could reveal
/// the protocol in use".
///
/// A 9000-byte pad makes that single write burst roughly **9.3 KB** — past the
/// point where an Ethernet path will segment it into several packets, which is
/// the exact outcome the rule exists to prevent. Choosing 256 instead bounds
/// the worst case at
///
/// ```text
///   salt      32   (16 for 2022-blake3-aes-128-gcm)
///   fixed     11 + 16 tag
///   variable  259 (longest address) + 2 (padding length) + 256 (padding) + 16 tag
///   ------------------------------------------------------------------
///   total     592 bytes
/// ```
///
/// which is one Ethernet frame on any path with an MTU of 1500 or more.
///
/// **This is one named constant with one owner on purpose.** RFC-012 §12.1 is
/// the precedent: two unowned restatements of the same rule let the writer and
/// the reader disagree about the wire format while every tail-only test stayed
/// green. A reader must accept up to [`MAX_PADDING_LENGTH`] — it cannot know
/// this project's policy, and rejecting a longer pad would break interoperability
/// — but it must never accept more than that, and this writer never emits more
/// than this.
pub const REQUEST_PADDING_MAX_BYTES: usize = 256;

/// The largest single write a request opener can produce: salt plus both header
/// chunks, with [`REQUEST_PADDING_MAX_BYTES`] of padding. See that constant for
/// the derivation; it is a `const` so the test that pins the burst cannot drift
/// from the policy without failing.
pub const MAX_REQUEST_HEADER_BURST: usize = 32
    + (11 + PAYLOAD_CHUNK_OVERHEAD)
    + (MAX_SOCKS5_ADDR_LEN + 2 + REQUEST_PADDING_MAX_BYTES + PAYLOAD_CHUNK_OVERHEAD);

/// Total length of the SOCKS5 address whose ATYP byte is `atyp`, given the
/// domain length in `domain_len`.
///
/// ATYP 1 (IPv4) is 1+4+2 = 7, ATYP 4 (IPv6) is 1+16+2 = 19, and ATYP 3
/// (domain) is 1+1+len+2. `None` for an ATYP this code does not implement,
/// which the caller must treat as a protocol error rather than guess at.
///
/// This is the **only** place the address length is derived. The writer needs
/// it to find where the address ends in a buffer the caller is still writing
/// into, and the reader needs it to find where the padding length starts. Those
/// are two call sites for one wire rule, and RFC-012 §12.1 is the precedent for
/// what happens when they each keep their own copy: the two ends disagree about
/// the format while every tail-only test stays green.
pub fn socks5_addr_len(atyp: u8, domain_len: Option<u8>) -> Option<usize> {
    match atyp {
        1 => Some(7),
        4 => Some(19),
        3 => domain_len.map(|n| 2 + n as usize + 2),
        _ => None,
    }
}

/// The variable-length header of a request stream, split per section 3.1.3.
///
/// Section 3.1.3 defines the chunk as
/// `ATYP | address | port | padding length (u16be) | padding | initial payload`.
/// Those last three fields are not part of the address, and a reader that hands
/// the whole chunk upward delivers a conformant peer's padding as the first
/// bytes of its payload — silent corruption, not a rejection. So the split
/// happens here, once, and the caller receives the two halves by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableHeader {
    /// `ATYP | address | port`, and nothing else. This is what the transport
    /// above parses as the target address, byte for byte.
    pub address: Vec<u8>,
    /// The initial payload that followed the padding, if any. Section 3.1.4
    /// requires that "either initial payload or padding MUST be present", so a
    /// conformant peer may legitimately send its first application bytes inside
    /// the header chunk. They are delivered, never discarded.
    pub initial_payload: Vec<u8>,
}

/// Assemble a request's variable-length header from an address and a pad.
///
/// The writer's half of the single owner: `build_variable_header` and
/// [`split_variable_header`] are inverses, and both apply the same two §3.1.4
/// rules, so a change to one cannot leave the other describing a different
/// format.
///
/// `pad` may be empty — a peer that has payload available may put it in the
/// chunk instead and satisfy the MUST that way — but `pad` and an initial
/// payload must not *both* be absent. Since this function has no payload
/// parameter, an empty `pad` is only legal when the caller has an initial
/// payload to send in a later chunk; that is the caller's half of the rule and
/// [`split_variable_header`] enforces it on the way back in.
pub fn build_variable_header(address: &[u8], pad: &[u8]) -> Result<Vec<u8>, HeaderError> {
    if pad.len() > MAX_PADDING_LENGTH {
        return Err(HeaderError::BadLength);
    }
    // The address must itself be well formed, because it is the first field and
    // nothing downstream re-checks it.
    let atyp = *address.first().ok_or(HeaderError::BadLength)?;
    let domain_len = if atyp == 3 { address.get(1).copied() } else { None };
    socks5_addr_len(atyp, domain_len).ok_or(HeaderError::BadLength)?;

    let mut out = Vec::with_capacity(address.len() + 2 + pad.len());
    out.extend_from_slice(address);
    out.extend_from_slice(&(pad.len() as u16).to_be_bytes());
    out.extend_from_slice(pad);
    Ok(out)
}

/// Draw this request's padding: a length uniform over
/// `1..=REQUEST_PADDING_MAX_BYTES` and that many CSPRNG bytes.
///
/// Uniform over the whole inclusive range rather than `0..` or a byte, because
/// the inclusive range is what keeps the distribution flat — `1 + x % 256` over
/// a byte is uniform, but anything that reaches `REQUEST_PADDING_MAX_BYTES`
/// through `as u8` would silently halve the top half.
///
/// The length is never zero: §3.1.4 requires padding to be non-zero when there
/// is no initial payload, and this writer never ships one in the header chunk,
/// so zero would make every request it opens non-conformant.
pub fn draw_request_padding() -> Vec<u8> {
    let len = 1 + (rand::random::<u16>() as usize % REQUEST_PADDING_MAX_BYTES);
    crate::secure_random_bytes(len).unwrap_or_else(|| {
        // OS entropy unavailable. Fail safe rather than silent: a zero pad
        // length here would make every request non-conformant, and a zero-filled
        // pad is worse still. A repeated-but-nonzero pad still satisfies §3.1.4;
        // the writer has no error channel from a `Vec`-returning helper, and the
        // read side will simply find a pad of the wrong size.
        vec![0xA5u8; len]
    })
}

/// Split a decrypted variable-length header chunk into the address and the
/// initial payload, enforcing both §3.1.4 server MUSTs.
///
/// The reader's half of the single owner:
///
/// - "Servers MUST reject the request if the variable-length header chunk does
///   not contain payload and the padding length is 0."
/// - "Servers MUST enforce that the request header (including padding) does not
///   extend beyond the header chunks."
///
/// plus §3.1.3's `MaxPaddingLength = 9000`, which bounds the field independently
/// of whether the bytes happen to be present.
///
/// Every rejection is [`HeaderError::BadLength`] or [`HeaderError::Truncated`],
/// which render identically — see the note on `HeaderError` about not becoming a
/// probing oracle.
pub fn split_variable_header(chunk: &[u8]) -> Result<VariableHeader, HeaderError> {
    let atyp = *chunk.first().ok_or(HeaderError::Truncated)?;
    let domain_len = if atyp == 3 { chunk.get(1).copied() } else { None };
    let addr_len = socks5_addr_len(atyp, domain_len).ok_or(HeaderError::BadLength)?;
    if chunk.len() < addr_len + 2 {
        // Either the address runs past the chunk, or the chunk ends before the
        // two-byte padding-length field. §3.1.4's second MUST: the header must
        // not extend beyond the header chunks, and here it cannot even be read.
        return Err(HeaderError::BadLength);
    }
    let pad_len = u16::from_be_bytes([chunk[addr_len], chunk[addr_len + 1]]) as usize;
    if pad_len > MAX_PADDING_LENGTH {
        return Err(HeaderError::BadLength);
    }
    let after_pad = addr_len + 2 + pad_len;
    if chunk.len() < after_pad {
        // §3.1.4's second MUST, in the form that actually matters: the padding
        // length is declared and the bytes are not there. Clamping instead would
        // silently deliver a different address to the transport above.
        return Err(HeaderError::BadLength);
    }
    let initial_payload = chunk[after_pad..].to_vec();
    // §3.1.4's first MUST. Checked last, because it is the only one that needs
    // the split to have succeeded before it can be evaluated at all.
    if pad_len == 0 && initial_payload.is_empty() {
        return Err(HeaderError::BadLength);
    }
    Ok(VariableHeader { address: chunk[..addr_len].to_vec(), initial_payload })
}

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
    /// Encoded size: 1 type + 8 timestamp + salt + 2 length.
    ///
    /// Section 3.1.2 states the response header chunk is "27/43B + 16B tag" for
    /// a 16/32-byte salt, and that reconciles exactly with the field list in
    /// section 3.1.3: 1 + 8 + 16 + 2 = 27, and 1 + 8 + 32 + 2 = 43. The stated
    /// totals exclude the tag. An earlier version of this comment claimed the
    /// arithmetic did not reconcile and treated the layout as a guess; it does,
    /// and the layout below is the specified one.
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
///
/// # Why the primitive is a parameter
///
/// This is the *only* function in the crate that knows a request stream begins
/// with two standalone header chunks. Two callers need it and they hold
/// different AEAD primitives: this module's callers hold a [`NonceCounter`] plus
/// a subkey, while [`crate::protocol::shadowsocks::ShadowsocksStream`] holds a
/// `ring` key whose nonce schedule is internal. Passing the single-chunk AEAD
/// in lets both call one implementation of the *framing*, which is the part
/// that was got wrong, instead of each re-deriving a header layout of its own.
/// See [`seal_request_headers_with`] for the primitive-taking form and
/// [`seal_request_headers`] for the counter-taking wrapper.
pub fn seal_request_headers(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    timestamp: u64,
    variable: &[u8],
) -> Result<Vec<u8>, HeaderError> {
    seal_request_headers_with(timestamp, variable, |chunk| {
        Ok(seal(method, subkey, &counter.next()?, b"", chunk)?)
    })
}

/// The framing of [`seal_request_headers`], with the single-chunk AEAD supplied
/// by the caller and invoked once per chunk.
///
/// `seal` is called exactly twice, in order, with the fixed-length header and
/// then the variable-length header. A caller that folds them into one AEAD
/// operation — which is what `ShadowsocksStream` used to do — cannot call this,
/// because the call count *is* the property being specified.
///
/// # The variable-length header, section 3.1.3
///
/// `variable` here is the **SOCKS5 address**, not the whole variable-length
/// header. This function appends `padding length (u16be) | padding` to it via
/// [`build_variable_header`], which is the same owner [`split_variable_header`]
/// reads it back with. The padding length is drawn by [`draw_request_padding`]
/// and is never zero, so §3.1.4's "either initial payload or padding MUST be
/// present" is satisfied without this writer ever shipping an initial payload —
/// which is deliberate, because putting payload in the header chunk would couple
/// header emission to caller timing for no benefit the MUST requires.
pub fn seal_request_headers_with<E>(
    timestamp: u64,
    variable: &[u8],
    mut seal: E,
) -> Result<Vec<u8>, HeaderError>
where
    E: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    let pad = draw_request_padding();
    let header = build_variable_header(variable, &pad)?;
    if header.len() > MAX_CHUNK_LEN {
        return Err(HeaderError::BadLength);
    }
    // Fixed-length header: type, timestamp, and the length of the variable part.
    let fixed = RequestHeader {
        stream_type: StreamType::ClientStream,
        timestamp,
        length: header.len() as u16,
    }
    .encode();

    let mut out = Vec::with_capacity(fixed.len() + header.len() + 2 * PAYLOAD_CHUNK_OVERHEAD);
    out.extend_from_slice(&seal(&fixed)?);
    out.extend_from_slice(&seal(&header)?);
    Ok(out)
}

/// Read a request stream's headers.
///
/// Returns the split variable-length header — the address, and the initial
/// payload that must be delivered rather than discarded — and the number of
/// bytes consumed.
pub fn read_request_headers(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    counter: &mut NonceCounter,
    buf: &mut BytesMut,
    now: u64,
) -> Result<(VariableHeader, usize), HeaderError> {
    let before = buf.len();
    let variable = read_request_headers_with(now, buf, |chunk| {
        Ok(open(method, subkey, &counter.next()?, b"", chunk)?)
    })?;
    let consumed = before - buf.len();
    Ok((variable, consumed))
}

/// The framing of [`read_request_headers`], with the single-chunk AEAD supplied
/// by the caller and invoked once per chunk.
///
/// `open` is called exactly twice, in order. It must authenticate the
/// fixed-length header chunk before the fixed header is parsed, and must return
/// the plaintext of the variable-length header chunk. The caller is responsible
/// for having `buf` hold the whole of both chunks: this function cannot report
/// "not enough bytes yet" through a closure that must be called an exact number
/// of times, so it reports [`HeaderError::Truncated`] instead.
///
/// The chunk's plaintext is split by [`split_variable_header`], which enforces
/// both §3.1.4 server MUSTs. Returning it whole — which is what this used to do
/// — meant a conformant peer's padding length and padding reached the caller as
/// if they were part of the target address.
pub fn read_request_headers_with<R>(
    now: u64,
    buf: &mut BytesMut,
    mut open: R,
) -> Result<VariableHeader, HeaderError>
where
    R: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    // Fixed header: 11 bytes plus a tag.
    if buf.len() < 11 + 16 {
        return Err(HeaderError::Truncated);
    }
    let fixed = open(&buf[..11 + 16])?;
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
    let variable = open(&buf[start..start + need])?;
    buf.advance(start + need);
    split_variable_header(&variable)
}

/// Encoded size of the request stream's fixed-length header chunk: 11 bytes of
/// plaintext plus the tag.
pub const REQUEST_FIXED_CHUNK_LEN: usize = 11 + PAYLOAD_CHUNK_OVERHEAD;

/// Read the fixed-length chunk of a request stream and return the declared
/// length of the variable-length chunk that follows.
///
/// The incremental counterpart of the first half of [`read_request_headers_with`],
/// and the same owner of the rules: the chunk must authenticate before its
/// plaintext is parsed, the type byte must be a client stream, and the timestamp
/// must be within the skew window. A stream that buffers across socket reads
/// cannot use the two-chunk helper, because it cannot express "not enough bytes
/// yet" through a closure that must run an exact number of times.
pub fn read_request_fixed_header_with<R>(
    buf: &mut BytesMut,
    now: u64,
    mut open: R,
) -> Result<u16, HeaderError>
where
    R: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    if buf.len() < REQUEST_FIXED_CHUNK_LEN {
        return Err(HeaderError::Truncated);
    }
    let fixed = open(&buf[..REQUEST_FIXED_CHUNK_LEN])?;
    let header = RequestHeader::decode(&fixed).ok_or(HeaderError::BadStreamType)?;

    // A server stream header must not be accepted where a request is expected.
    // This is the direction byte doing its job: without it a response header is
    // replayable as a request.
    if header.stream_type != StreamType::ClientStream {
        return Err(HeaderError::BadStreamType);
    }
    check_timestamp(header.timestamp, now)?;

    if header.length as usize > MAX_CHUNK_LEN {
        return Err(HeaderError::BadLength);
    }
    buf.advance(REQUEST_FIXED_CHUNK_LEN);
    Ok(header.length)
}

/// Read the variable-length chunk of a request stream after
/// [`read_request_fixed_header_with`] declared its length, and split it per
/// section 3.1.3.
///
/// The incremental counterpart of [`read_request_headers_with`], and the same
/// owner of the rules: the chunk is authenticated before it is parsed, and
/// [`split_variable_header`] enforces both §3.1.4 server MUSTs on the plaintext.
pub fn read_request_variable_header_with<R>(
    len: u16,
    buf: &mut BytesMut,
    mut open: R,
) -> Result<VariableHeader, HeaderError>
where
    R: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    let need = len as usize + PAYLOAD_CHUNK_OVERHEAD;
    if buf.len() < need {
        return Err(HeaderError::Truncated);
    }
    let variable = open(&buf[..need])?;
    buf.advance(need);
    split_variable_header(&variable)
}

/// Seal a response stream's single header chunk, section 3.1.2.
///
/// A response stream needs one header chunk, and it doubles as the first length
/// chunk: `length` is the plaintext length of the payload chunk that follows it,
/// so a reader knows that chunk's size from the header alone and never has to
/// guess where a variable-length ciphertext ends.
///
/// This is the counterpart of [`seal_request_headers_with`] and exists for the
/// same reason: `ShadowsocksStream` serves both ends of a proxied connection
/// from one type, so both directions need the header framing owned here rather
/// than reimplemented.
pub fn seal_response_header_with<E>(
    timestamp: u64,
    request_salt: &[u8],
    length: u16,
    mut seal: E,
) -> Result<Vec<u8>, HeaderError>
where
    E: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    if request_salt.len() > MAX_CHUNK_LEN {
        return Err(HeaderError::BadLength);
    }
    let body = ResponseHeader {
        stream_type: StreamType::ServerStream,
        timestamp,
        request_salt: request_salt.to_vec(),
        length,
    }
    .encode();
    seal(&body)
}

/// Read a response stream's header chunk, section 3.1.2.
///
/// Returns the echoed request salt and the declared length of the payload chunk
/// that follows. The salt echo is checked by the caller, which is the only
/// place that knows which salt it sent.
pub fn read_response_header_with<R>(
    salt_len: usize,
    buf: &mut BytesMut,
    now: u64,
    mut open: R,
) -> Result<(Vec<u8>, u16), HeaderError>
where
    R: FnMut(&[u8]) -> Result<Vec<u8>, HeaderError>,
{
    let need = 11 + salt_len + PAYLOAD_CHUNK_OVERHEAD;
    if buf.len() < need {
        return Err(HeaderError::Truncated);
    }
    let body = open(&buf[..need])?;
    let header = ResponseHeader::decode(&body, salt_len).ok_or(HeaderError::BadStreamType)?;

    // A client stream header must not be accepted where a response is expected.
    if header.stream_type != StreamType::ServerStream {
        return Err(HeaderError::BadStreamType);
    }
    check_timestamp(header.timestamp, now)?;
    buf.advance(need);
    Ok((header.request_salt, header.length))
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

    /// A well-formed SOCKS5 IPv4 address. Section 3.1.3's variable-length
    /// header starts with one, and the builder now validates it rather than
    /// sealing whatever it is handed.
    const V4_ADDR: &[u8] = b"\x01\x5d\xb8\xd8\x22\x01\xbb";

    #[test]
    fn request_headers_round_trip() {
        for m in METHODS {
            let key = keys(m);
            let mut c = NonceCounter::default();
            let now = 1_700_000_000u64;
            let sealed = seal_request_headers(m, &key, &mut c, now, V4_ADDR).unwrap();
            let mut buf = BytesMut::from(&sealed[..]);
            let mut reader = NonceCounter::default();
            let (got, consumed) =
                read_request_headers(m, &key, &mut reader, &mut buf, now).unwrap();
            assert_eq!(got.address, V4_ADDR, "{m:?}: the address must round-trip");
            assert!(
                got.initial_payload.is_empty(),
                "{m:?}: this writer ships padding, not an initial payload"
            );
            assert_eq!(consumed, sealed.len());
            assert!(buf.is_empty());
        }
    }

    /// Section 3.1.4's single-write rule and this project's MTU bound, as one
    /// number. A writer that drew more padding than
    /// [`REQUEST_PADDING_MAX_BYTES`] would push the burst past a 1500-byte MTU,
    /// and TCP would segment the burst back into the small packets the rule
    /// exists to prevent.
    #[test]
    fn the_request_header_burst_fits_one_ethernet_frame() {
        // The longest address any ATYP can produce, at the widest padding.
        let mut addr = vec![3u8, 255];
        addr.extend(std::iter::repeat_n(b'x', 255));
        addr.extend_from_slice(&[0x01, 0xBB]);
        assert_eq!(addr.len(), MAX_SOCKS5_ADDR_LEN);
        let pad = vec![0u8; REQUEST_PADDING_MAX_BYTES];
        let variable = build_variable_header(&addr, &pad).unwrap();

        // salt + both header chunks + the tag on each, which is what §3.1.4
        // requires to go out in one write.
        let burst = 32 + (11 + PAYLOAD_CHUNK_OVERHEAD) + (variable.len() + PAYLOAD_CHUNK_OVERHEAD);
        assert_eq!(
            burst, MAX_REQUEST_HEADER_BURST,
            "the constant and the arithmetic must not drift apart"
        );
        assert!(burst <= 1500, "the burst is {burst} bytes; one MTU is 1500");
    }

    #[test]
    fn two_header_chunks_consume_two_counter_values() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let mut c = NonceCounter::default();
        seal_request_headers(m, &key, &mut c, 1_700_000_000, V4_ADDR).unwrap();
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
        frame.extend_from_slice(&seal(m, &key, &c.next().unwrap(), b"", V4_ADDR).unwrap());
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
        let sealed = seal_request_headers(m, &key, &mut c, old, V4_ADDR).unwrap();
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
        let sealed = seal_request_headers(m, &key, &mut c, old, V4_ADDR).unwrap();
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
        let sealed = seal_request_headers(m, &key, &mut c, 1_700_000_000, V4_ADDR).unwrap();
        let mut buf = BytesMut::from(&sealed[..sealed.len() - 1]);
        let mut reader = NonceCounter::default();
        assert_eq!(
            read_request_headers(m, &key, &mut reader, &mut buf, 1_700_000_000),
            Err(HeaderError::Truncated)
        );
    }

    // ---- the variable-length header, section 3.1.3 -------------------------
    //
    // `ATYP | address | port | padding length (u16be) | padding | initial
    // payload`. Every test here drives the reader over a wire built by hand from
    // that field list, so a defect in this module's own writer cannot make them
    // pass.

    /// Build a request stream whose variable-length header chunk is exactly
    /// `variable`, with the two header chunks sealed per §3.1.2.
    fn request_wire(
        m: Shadowsocks2022Method,
        key: &[u8],
        timestamp: u64,
        variable: &[u8],
    ) -> (Vec<u8>, NonceCounter) {
        let mut c = NonceCounter::default();
        let fixed = RequestHeader {
            stream_type: StreamType::ClientStream,
            timestamp,
            length: variable.len() as u16,
        }
        .encode();
        let mut wire = seal(m, key, &c.next().unwrap(), b"", &fixed).unwrap();
        wire.extend_from_slice(&seal(m, key, &c.next().unwrap(), b"", variable).unwrap());
        (wire, c)
    }

    /// The reader returns **only** `ATYP | address | port` upward, and delivers
    /// the initial payload separately rather than leaving it inside the chunk.
    ///
    /// The transport above reads the address off the front of this stream
    /// (`transport::inbound/shadowsocks.rs` parses it by hand), so returning the
    /// whole chunk hands it a padding-length field as if it were part of the
    /// address — silent corruption, not a rejection.
    #[test]
    fn the_reader_returns_the_address_and_not_the_whole_chunk() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let addr = b"\x01\x5d\xb8\xd8\x22\x01\xbb".to_vec();

        for (pad_len, initial) in
            [(1usize, &b""[..]), (37, &b""[..]), (0, &b"GET / HTTP/1.1\r\n"[..])]
        {
            let pad: Vec<u8> = (0..pad_len).map(|i| (i as u8) ^ 0x5C).collect();
            let mut variable = addr.clone();
            variable.extend_from_slice(&(pad_len as u16).to_be_bytes());
            variable.extend_from_slice(&pad);
            variable.extend_from_slice(initial);

            let (wire, _) = request_wire(m, &key, now, &variable);
            let mut buf = BytesMut::from(&wire[..]);
            let mut reader = NonceCounter::default();
            let (got, consumed) = read_request_headers(m, &key, &mut reader, &mut buf, now)
                .expect("conformant header");
            assert_eq!(
                got.address,
                addr,
                "pad_len {pad_len}, initial {}: the reader must return the address only",
                initial.len()
            );
            assert_eq!(
                got.initial_payload, initial,
                "pad_len {pad_len}: the initial payload must come back whole"
            );
            assert_eq!(consumed, wire.len(), "pad_len {pad_len}: whole header consumed");
            assert!(buf.is_empty());
        }
    }

    /// The negative that both implementations used to violate: the bare address,
    /// with no padding-length field at all.
    ///
    /// §3.1.4: "Servers MUST reject the request if the variable-length header
    /// chunk does not contain payload and the padding length is 0." A chunk that
    /// ends after the port cannot supply a padding length, so it cannot satisfy
    /// the MUST, and the server must close.
    #[test]
    fn a_bare_address_variable_chunk_is_rejected() {
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let (wire, _) = request_wire(m, &key, now, b"\x01\x5d\xb8\xd8\x22\x01\xbb");
        let mut buf = BytesMut::from(&wire[..]);
        let mut reader = NonceCounter::default();
        assert!(
            read_request_headers(m, &key, &mut reader, &mut buf, now).is_err(),
            "a variable-length header chunk with no padding-length field must be rejected"
        );
    }

    /// §3.1.4, first server MUST: padding length 0 with no initial payload.
    #[test]
    fn zero_padding_with_no_initial_payload_is_rejected() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let mut variable = b"\x01\x5d\xb8\xd8\x22\x01\xbb".to_vec();
        variable.extend_from_slice(&0u16.to_be_bytes());
        let (wire, _) = request_wire(m, &key, now, &variable);
        let mut buf = BytesMut::from(&wire[..]);
        let mut reader = NonceCounter::default();
        assert!(
            read_request_headers(m, &key, &mut reader, &mut buf, now).is_err(),
            "padding length 0 with no initial payload must be rejected"
        );
    }

    /// §3.1.4, second server MUST: "the request header (including padding) does
    /// not extend beyond the header chunks." A declared padding length larger
    /// than the chunk holds is exactly that, and clamping it would silently
    /// deliver the wrong bytes.
    #[test]
    fn padding_extending_past_the_chunk_is_rejected() {
        let m = Shadowsocks2022Method::ChaCha20Poly1305;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let mut variable = b"\x01\x5d\xb8\xd8\x22\x01\xbb".to_vec();
        variable.extend_from_slice(&4096u16.to_be_bytes());
        variable.extend_from_slice(&[0xABu8; 8]);
        let (wire, _) = request_wire(m, &key, now, &variable);
        let mut buf = BytesMut::from(&wire[..]);
        let mut reader = NonceCounter::default();
        assert!(
            read_request_headers(m, &key, &mut reader, &mut buf, now).is_err(),
            "a padding length past the end of the header chunks must be rejected"
        );
    }

    /// §3.1.3: `MaxPaddingLength = 9000`. The bound is written out longhand here
    /// so the test is an independent statement of the specification rather than
    /// an echo of whatever this module's constant happens to be.
    #[test]
    fn a_padding_length_above_the_specification_maximum_is_rejected() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let mut variable = b"\x01\x5d\xb8\xd8\x22\x01\xbb".to_vec();
        variable.extend_from_slice(&9001u16.to_be_bytes());
        variable.extend_from_slice(&[0u8; 4096]);
        let (wire, _) = request_wire(m, &key, now, &variable);
        let mut buf = BytesMut::from(&wire[..]);
        let mut reader = NonceCounter::default();
        assert!(
            read_request_headers(m, &key, &mut reader, &mut buf, now).is_err(),
            "MaxPaddingLength is 9000; 9001 must be refused even though the bytes are present"
        );
    }

    /// Every padding length in the project's range, exhaustively. A sampled test
    /// would leave the defective length unverified, which is the whole class of
    /// bug — the same reasoning as `padding::every_pad_length_round_trips`.
    #[test]
    fn every_request_padding_length_round_trips() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let key = keys(m);
        let now = 1_700_000_000u64;
        let addr = b"\x03\x0bexample.com\x01\xbb".to_vec();
        for pad_len in 1..=REQUEST_PADDING_MAX_BYTES {
            let pad: Vec<u8> = (0..pad_len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let mut variable = addr.clone();
            variable.extend_from_slice(&(pad_len as u16).to_be_bytes());
            variable.extend_from_slice(&pad);
            let (wire, _) = request_wire(m, &key, now, &variable);
            let mut buf = BytesMut::from(&wire[..]);
            let mut reader = NonceCounter::default();
            let (got, consumed) = read_request_headers(m, &key, &mut reader, &mut buf, now)
                .unwrap_or_else(|e| {
                    panic!("pad_len {pad_len}: rejected a conformant header: {e:?}")
                });
            assert_eq!(got.address, addr, "pad_len {pad_len}: the address must survive");
            assert!(
                got.initial_payload.is_empty(),
                "pad_len {pad_len}: there was no initial payload"
            );
            assert_eq!(consumed, wire.len(), "pad_len {pad_len}: whole header consumed");
            assert!(buf.is_empty(), "pad_len {pad_len}: trailing bytes left behind");
        }
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
            wire.extend_from_slice(&seal_request_headers(m, &key, &mut c, now, V4_ADDR).unwrap());
            wire.extend_from_slice(&seal_chunk(m, &key, &mut c, b"payload-one").unwrap());
            wire.extend_from_slice(&seal_chunk(m, &key, &mut c, b"payload-two").unwrap());

            let mut buf = BytesMut::from(&wire[..]);
            let mut reader = NonceCounter::default();
            let (var, _) = read_request_headers(m, &key, &mut reader, &mut buf, now).unwrap();
            assert_eq!(var.address, V4_ADDR);
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
