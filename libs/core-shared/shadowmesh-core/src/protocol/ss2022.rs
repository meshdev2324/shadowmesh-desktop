//! Shadowsocks-2022 (SIP022) message headers, subkey derivation, and the
//! SIP022 section 3.2 / 4.1 UDP packet protocol.
//!
//! Clean-room, written from <https://shadowsocks.org/doc/sip022.html>. No
//! third-party Shadowsocks implementation was consulted or ingested; see
//! `design/protocol-rules.md` (Independent Implementation Policy).
//!
//! # What used to be wrong here, and is now removed
//!
//! This module previously owned its own `derive_session_subkey`, which derived
//! the session subkey as
//! `blake3::derive_key("shadowmesh-ss2022-subkey", salt || key)`.
//!
//! Both halves of that were wrong against SIP022 section 2.2, which specifies
//! `blake3::derive_key("shadowsocks 2022 session subkey", key + salt)`:
//!
//! - the context string was an invented one that never appears on the wire, so
//!   no conforming peer could ever derive the same subkey; and
//! - the key material was concatenated in the opposite order, so even a peer
//!   that guessed the context string would still disagree.
//!
//! It duplicated `transport::shadowsocks2022::derive_session_subkey`, which
//! already implements the normative form and is pinned by vectors computed
//! independently from §2.2. The duplicate has been **deleted**, not corrected:
//! two subkey derivations in one crate is precisely how the drift happened in
//! the first place. Everything that needs a 2022 subkey now calls the one
//! normative function.
//!
//! # Why UDP does not reuse the stream framing
//!
//! Shadowsocks 2022 has two genuinely different UDP constructions, and neither
//! is the SIP007 single-packet format that `protocol::shadowsocks` implements:
//!
//! - **Sections 3.2.1 - 3.2.2 (the two AES methods).** A packet is a 16-byte
//!   *separate header* encrypted with one raw AES block under the pre-shared
//!   key, followed by an AEAD body. The separate header is
//!   `[session ID:8][packet ID:u64be]`. Bytes `[0..8]` are the salt for the
//!   session subkey and bytes `[4..16]` are the body AEAD's nonce. The body is
//!   the main header plus payload, sealed in a *single* AEAD operation.
//! - **Section 4.1 (the ChaCha method).** No separate header at all. The
//!   packet starts with a random 24-byte XChaCha20-Poly1305 nonce, the
//!   pre-shared key is used directly with no subkey derivation, and the
//!   session ID and packet ID move *into* the main header.
//!
//! There is no length chunk in either. Nothing is needed to frame a datagram:
//! UDP is message-oriented and the AEAD tag delimits the ciphertext. A trailing
//! or separately-AEAD'd length block would be an invention.
//!
//! # Replay protection, and why it is shaped the way it is
//!
//! Section 3.2.4 requires, per relay session:
//!
//! 1. a **sliding window filter** over packet IDs, rejecting duplicates and
//!    out-of-window IDs;
//! 2. that the window **must not** be updated before the packet passes header
//!    validation; and
//! 3. a **30-second timestamp** check, "messages with over 30 seconds of time
//!    difference MUST be treated as replay" (section 3.2.3).
//!
//! The window is what makes this different from the TCP path. A TCP stream has
//! no packet ID: its replay defence is the nonce counter plus the 60-second
//! salt pool, because a stream's frames are chained by the counter's
//! progression. A UDP packet has no chaining to lean on - each datagram carries
//! its own nonce - so the packet ID *is* the counter, and without a window an
//! attacker can replay an arbitrary captured packet verbatim and it will
//! decrypt. So the window genuinely applies here, keyed on the packet ID rather
//! than on a stream position. It is [`PacketIdWindow`], WireGuard's filter,
//! which the specification explicitly permits.
//!
//! The ordering requirement (2) is the subtle one and is enforced by the API
//! shape: [`UdpReceiver::open`] performs decryption, header validation and the
//! window update as one indivisible step, so no caller can advance the window
//! on a packet that has not been authenticated *and* semantically validated.
//!
//! Reuse: [`SaltPool`] and [`check_timestamp`] are re-exported from
//! `protocol::ss2022_stream`. Both are exactly what section 3.2.4/3.2.3 wants -
//! 60-second salt retention with no false positives, and a two-sided 30-second
//! skew check on a `u64` second clock. The stream's own fixed-header helpers
//! are deliberately **not** reused for UDP: they describe the section 3.1.3
//! stream header, which has a different shape from the section 3.2 packet
//! header, and the two are not interchangeable.

// ---------------------------------------------------------------------------
// Reuse from the stream layer (SIP022 sections 3.1.5 / 3.2.3 / 3.2.4)
// ---------------------------------------------------------------------------

/// 60-second salt retention with no false positives (section 3.1.5). A UDP
/// session's identity *is* a salt - the 8-byte session ID - so this pool is
/// what a server uses to notice a session being replayed, and what it uses to
/// keep a session alive for at least 60 seconds.
pub use crate::protocol::ss2022_stream::{check_timestamp, SaltPool, MAX_TIME_SKEW_SECS};

// ---------------------------------------------------------------------------
// Identity parsing
// ---------------------------------------------------------------------------

/// Parses a 2022-edition identity: the config "password" is the base64
/// encoding of the raw master key (SIP022-family). Enforces the expected
/// byte length; rejects anything that is not well-formed base64 of the right
/// size so a misconfigured key can never silently fall back.
pub fn parse_identity_key(configured: &str, expected_len: usize) -> Result<Vec<u8>, &'static str> {
    use base64::Engine;
    let trimmed = configured.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| "identity must be the base64-encoded master key")?;
    if bytes.len() != expected_len {
        return Err("identity key length mismatch");
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Stream fixed-length header (SIP022 section 3.1.3)
// ---------------------------------------------------------------------------
//
// The fixed-length *stream* header lives in `protocol::ss2022_stream`, which is
// its single owner: `RequestHeader` / `ResponseHeader`, the two standalone
// header chunks, and the skew check that guards them.
//
// A second, millisecond-valued copy used to live here as
// `build_fixed_header` / `parse_fixed_header` / `FixedHeader::is_fresh`, and the
// stream writer used it. It was wrong in a way no test in this crate could see:
// SIP022 section 3.1.1 specifies **seconds**, and a millisecond timestamp is
// ~1.7e12 seconds away from a conformant receiver's clock, so every header
// authenticated perfectly and was still rejected as stale by every peer. The
// helpers are removed rather than left in place: two owners of one wire format,
// disagreeing about its units, is how that happened.

// ---------------------------------------------------------------------------
// UDP packet protocol (SIP022 sections 3.2 and 4.1)
// ---------------------------------------------------------------------------

use crate::transport::shadowsocks2022::{
    derive_packet_subkey, open_separate_header, open_xchacha, seal, seal_separate_header,
    seal_xchacha, Shadowsocks2022Error, Shadowsocks2022Method,
};
pub use crate::transport::shadowsocks2022::{
    UDP_SEPARATE_HEADER_LEN, UDP_SESSION_ID_LEN, UDP_TAG_LEN, XCHACHA_NONCE_LEN,
};

/// `HeaderTypeClientPacket = 0`, section 3.2.3.
pub const PACKET_TYPE_CLIENT: u8 = 0;
/// `HeaderTypeServerPacket = 1`, section 3.2.3.
pub const PACKET_TYPE_SERVER: u8 = 1;

/// Main header, client to server: `type(1) | timestamp(8) | pad_len(2)`.
pub const MAIN_HEADER_LEN_CLIENT: usize = 1 + 8 + 2;
/// Main header, server to client: `type(1) | timestamp(8) | client_session_id(8) | pad_len(2)`.
pub const MAIN_HEADER_LEN_SERVER: usize = 1 + 8 + 8 + 2;

/// Section 3.2.4 permits WireGuard's filter, which this reproduces: a bitmap of
/// the 64 packet IDs immediately below the highest one seen.
pub const PACKET_ID_WINDOW_SIZE: u64 = 64;

/// Largest padding a main header can declare, from its `u16` length field.
pub const MAX_MAIN_HEADER_PADDING: usize = u16::MAX as usize;

/// Which way a packet is travelling. The type byte is what stops a
/// server-to-client packet being accepted where a client-to-server one is
/// expected, section 3.2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDirection {
    ClientToServer,
    ServerToClient,
}

impl UdpDirection {
    pub fn type_byte(self) -> u8 {
        match self {
            Self::ClientToServer => PACKET_TYPE_CLIENT,
            Self::ServerToClient => PACKET_TYPE_SERVER,
        }
    }

    /// Fixed part of the main header, before the optional client session ID.
    fn fixed_len(self) -> usize {
        match self {
            Self::ClientToServer => MAIN_HEADER_LEN_CLIENT,
            Self::ServerToClient => MAIN_HEADER_LEN_SERVER,
        }
    }
}

/// Why a UDP packet was refused.
///
/// `Display` is deliberately uninformative, matching the rest of the 2022
/// modules: an error that distinguishes "wrong key" from "stale timestamp" from
/// "replayed" is a probing oracle for an endpoint that is exposed to the open
/// internet. The variants are still distinct so internal callers and tests can
/// discriminate without anything reaching a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpPacketError {
    /// Shorter than the smallest legal packet for this construction.
    TooShort,
    /// AEAD tag verification failed, or the main header did not parse.
    Auth,
    /// The type byte does not match the direction this endpoint expects.
    WrongDirection,
    /// More than [`MAX_TIME_SKEW_SECS`] from the receiver's clock, in either
    /// direction.
    StaleTimestamp,
    /// A server-to-client packet named a client session ID this server session
    /// is not answering.
    ClientSessionMismatch,
    /// The sliding window filter rejected the packet ID.
    ReplayedPacket,
    /// The sender's `u64` packet counter is exhausted. Never wraps: a wrapped
    /// counter would repeat nonces, which is a total and silent loss of both
    /// confidentiality and authenticity.
    PacketIdExhausted,
    /// Padding length exceeds the bytes actually present.
    PaddingOverflowsBody,
    /// Section 3.2.2: a server session ID must not reuse a client session ID.
    ServerSessionReusesClientSession,
    /// The method's own error type, passed through.
    Crypto(Shadowsocks2022Error),
}

impl std::fmt::Display for UdpPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Opaque by design. See the type's doc comment.
        write!(f, "invalid SIP022 UDP packet")
    }
}

impl std::error::Error for UdpPacketError {}

impl From<Shadowsocks2022Error> for UdpPacketError {
    fn from(e: Shadowsocks2022Error) -> Self {
        match e {
            Shadowsocks2022Error::Authentication => Self::Auth,
            other => Self::Crypto(other),
        }
    }
}

impl From<crate::protocol::ss2022_stream::HeaderError> for UdpPacketError {
    fn from(e: crate::protocol::ss2022_stream::HeaderError) -> Self {
        use crate::protocol::ss2022_stream::HeaderError;
        match e {
            HeaderError::StaleTimestamp => Self::StaleTimestamp,
            HeaderError::Truncated => Self::TooShort,
            _ => Self::Auth,
        }
    }
}

// ---- packet ID sliding window (section 3.2.4) ----------------------------

/// WireGuard-style sliding window over packet IDs, as section 3.2.4 permits.
///
/// Tracks the highest packet ID seen plus a bitmap of the
/// [`PACKET_ID_WINDOW_SIZE`] IDs below it. Rejects exact duplicates and IDs that
/// have fallen out the bottom of the window - an ID more than 64 below the
/// highest is unrecoverable, because the bitmap cannot represent it, and
/// accepting it would reopen the replay hole the window exists to close.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketIdWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl PacketIdWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `packet_id` and reports whether it is new and in-window.
    ///
    /// Callers must only reach this after the packet has been authenticated and
    /// its main header validated; see [`UdpReceiver::open`].
    pub fn accept(&mut self, packet_id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(packet_id);
            self.bitmap = 1;
            return true;
        };
        if packet_id > highest {
            let shift = packet_id - highest;
            self.bitmap =
                if shift >= PACKET_ID_WINDOW_SIZE { 1 } else { (self.bitmap << shift) | 1 };
            self.highest = Some(packet_id);
            return true;
        }
        let delta = highest - packet_id;
        if delta >= PACKET_ID_WINDOW_SIZE {
            return false;
        }
        let mask = 1u64 << delta;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }

    /// Highest packet ID accepted so far, if any.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Forgets every packet ID. Only correct when the relay session itself has
    /// been torn down; using it to survive a single rejected packet would undo
    /// the replay protection it exists to provide.
    pub fn reset(&mut self) {
        self.highest = None;
        self.bitmap = 0;
    }
}

// ---- main header (section 3.2.3) -----------------------------------------

/// The decoded main header, which is the start of the AEAD-sealed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMainHeader {
    pub direction: UdpDirection,
    /// Unix epoch **seconds**. The specification states seconds for both the
    /// stream and the packet header, and `ss2022_stream::RequestHeader` agrees.
    pub timestamp: u64,
    /// Present on, and only on, server-to-client packets.
    pub client_session_id: Option<[u8; UDP_SESSION_ID_LEN]>,
    pub padding: Vec<u8>,
}

/// Builds a client-to-server body: main header, padding, then payload.
///
/// The bytes after the padding are the SOCKS5 address followed by the payload.
/// This layer does not parse the address: it is message framing, and the
/// address codec already exists in the transport layer. What matters here is
/// that padding and payload are inside the AEAD, so a peer cannot strip padding
/// without failing the tag.
pub fn build_client_body(
    timestamp: u64,
    padding: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, UdpPacketError> {
    if padding.len() > MAX_MAIN_HEADER_PADDING {
        return Err(UdpPacketError::PaddingOverflowsBody);
    }
    let mut body = Vec::with_capacity(MAIN_HEADER_LEN_CLIENT + padding.len() + payload.len());
    body.push(PACKET_TYPE_CLIENT);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    body.extend_from_slice(padding);
    body.extend_from_slice(payload);
    Ok(body)
}

/// Builds a server-to-client body, which additionally echoes the client session
/// ID so the client can bind the packet to the session that caused it.
pub fn build_server_body(
    timestamp: u64,
    client_session_id: &[u8; UDP_SESSION_ID_LEN],
    padding: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, UdpPacketError> {
    if padding.len() > MAX_MAIN_HEADER_PADDING {
        return Err(UdpPacketError::PaddingOverflowsBody);
    }
    let mut body = Vec::with_capacity(MAIN_HEADER_LEN_SERVER + padding.len() + payload.len());
    body.push(PACKET_TYPE_SERVER);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(client_session_id);
    body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    body.extend_from_slice(padding);
    body.extend_from_slice(payload);
    Ok(body)
}

/// Splits a decrypted body into its main header and the bytes after the
/// padding. Enforces that the padding does not run past the end of the body.
pub fn parse_main_header(
    body: &[u8],
    expected: UdpDirection,
) -> Result<(PacketMainHeader, &[u8]), UdpPacketError> {
    if body.len() < expected.fixed_len() {
        return Err(UdpPacketError::TooShort);
    }
    let mut cursor = 0usize;
    let type_byte = body[0];
    if type_byte != expected.type_byte() {
        return Err(UdpPacketError::WrongDirection);
    }
    cursor += 1;

    let timestamp = u64::from_be_bytes([
        body[cursor],
        body[cursor + 1],
        body[cursor + 2],
        body[cursor + 3],
        body[cursor + 4],
        body[cursor + 5],
        body[cursor + 6],
        body[cursor + 7],
    ]);
    cursor += 8;

    let client_session_id = match expected {
        UdpDirection::ClientToServer => None,
        UdpDirection::ServerToClient => {
            let mut id = [0u8; UDP_SESSION_ID_LEN];
            id.copy_from_slice(&body[cursor..cursor + UDP_SESSION_ID_LEN]);
            cursor += UDP_SESSION_ID_LEN;
            Some(id)
        }
    };

    let pad_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    let padding_end = cursor.checked_add(pad_len).ok_or(UdpPacketError::PaddingOverflowsBody)?;
    if padding_end > body.len() {
        return Err(UdpPacketError::PaddingOverflowsBody);
    }
    let padding = body[cursor..padding_end].to_vec();
    Ok((
        PacketMainHeader { direction: expected, timestamp, client_session_id, padding },
        &body[padding_end..],
    ))
}

// ---- packet sealing (sections 3.2.1, 3.2.2 and 4.1) ----------------------

/// A packet after its separate header and body have been recovered, but before
/// any replay or semantic validation. Returned by [`open_packet`] so a caller
/// can inspect it; [`UdpReceiver::open`] is the safe way to consume one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedPacket {
    pub session_id: [u8; UDP_SESSION_ID_LEN],
    pub packet_id: u64,
    pub header: PacketMainHeader,
    /// Bytes after the main header's padding: SOCKS5 address plus payload.
    pub payload: Vec<u8>,
}

/// Builds a UDP packet for the two AES methods (sections 3.2.1, 3.2.2).
///
/// ```text
/// packet := AES-block(psk, [session_id:8][packet_id:u64be])  (16 bytes)
///           || AEAD(blake3-subkey(psk, session_id), nonce=sep[4..16], body) || tag
/// ```
///
/// Note the asymmetry inside the separate header: bytes `[0..8]` seed the
/// subkey, bytes `[4..16]` are the nonce. The overlapping four bytes are what
/// tie the nonce to the session, so two sessions cannot collide on nonces even
/// though both count packet IDs from zero.
pub fn seal_packet(
    method: Shadowsocks2022Method,
    psk: &[u8],
    session_id: &[u8; UDP_SESSION_ID_LEN],
    packet_id: u64,
    body: &[u8],
) -> Result<Vec<u8>, UdpPacketError> {
    let mut separate = [0u8; UDP_SEPARATE_HEADER_LEN];
    separate[..UDP_SESSION_ID_LEN].copy_from_slice(session_id);
    separate[UDP_SESSION_ID_LEN..].copy_from_slice(&packet_id.to_be_bytes());

    let subkey = derive_packet_subkey(method, psk, session_id)?;
    let mut nonce = [0u8; crate::transport::shadowsocks2022::NONCE_LEN];
    nonce.copy_from_slice(&separate[4..16]);

    let sealed = seal_separate_header(method, psk, &separate)?;
    let body_ct = seal(method, &subkey, &nonce, b"", body)?;

    let mut out = Vec::with_capacity(UDP_SEPARATE_HEADER_LEN + body_ct.len());
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&body_ct);
    Ok(out)
}

/// Recovers the separate header and body of an AES-method packet.
///
/// `direction` is the direction this endpoint expects; it selects the main
/// header's layout and is checked against the packet's type byte.
///
/// **Does not** advance any replay state and does not check the timestamp.
/// Callers that want the specification's section 3.2.4 ordering guarantee must
/// use [`UdpReceiver::open`], which makes the whole sequence indivisible.
pub fn open_packet(
    method: Shadowsocks2022Method,
    psk: &[u8],
    direction: UdpDirection,
    wire: &[u8],
) -> Result<OpenedPacket, UdpPacketError> {
    if method == Shadowsocks2022Method::ChaCha20Poly1305 {
        return open_packet_xchacha(psk, direction, wire);
    }
    if wire.len() < UDP_SEPARATE_HEADER_LEN + UDP_TAG_LEN {
        return Err(UdpPacketError::TooShort);
    }
    let mut sealed = [0u8; UDP_SEPARATE_HEADER_LEN];
    sealed.copy_from_slice(&wire[..UDP_SEPARATE_HEADER_LEN]);
    let separate = open_separate_header(method, psk, &sealed)?;

    let mut session_id = [0u8; UDP_SESSION_ID_LEN];
    session_id.copy_from_slice(&separate[..UDP_SESSION_ID_LEN]);
    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&separate[UDP_SESSION_ID_LEN..]);
    let packet_id = u64::from_be_bytes(packet_id_bytes);

    let subkey = derive_packet_subkey(method, psk, &session_id)?;
    let mut nonce = [0u8; crate::transport::shadowsocks2022::NONCE_LEN];
    nonce.copy_from_slice(&separate[4..16]);

    let body = open_body(method, &subkey, &nonce, &wire[UDP_SEPARATE_HEADER_LEN..])?;
    finish_body(&body, session_id, packet_id, direction)
}

/// Builds a ChaCha-method packet (section 4.1).
///
/// No subkey derivation and no separate header: the packet is a random 24-byte
/// XChaCha20-Poly1305 nonce followed by the sealed body, keyed with the
/// pre-shared key directly. Session and packet IDs are carried in the body's
/// main header instead.
pub fn seal_packet_xchacha(
    psk: &[u8],
    nonce: &[u8; XCHACHA_NONCE_LEN],
    body: &[u8],
) -> Result<Vec<u8>, UdpPacketError> {
    let ct = seal_xchacha(psk, nonce, body)?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Recovers a ChaCha-method packet. The session and packet IDs come from the
/// ChaCha main header, which prefixes the padding-length field.
pub fn open_packet_xchacha(
    psk: &[u8],
    direction: UdpDirection,
    wire: &[u8],
) -> Result<OpenedPacket, UdpPacketError> {
    if wire.len() < XCHACHA_NONCE_LEN + UDP_TAG_LEN {
        return Err(UdpPacketError::TooShort);
    }
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce.copy_from_slice(&wire[..XCHACHA_NONCE_LEN]);
    let body = open_xchacha(psk, &nonce, &wire[XCHACHA_NONCE_LEN..])?;

    // Section 4.1 client header: session ID(8) packet ID(u64be) then the
    // type/timestamp main header. Server packets name a server session first.
    const PREFIX: usize = UDP_SESSION_ID_LEN + 8;
    if body.len() < PREFIX {
        return Err(UdpPacketError::TooShort);
    }
    let mut session_id = [0u8; UDP_SESSION_ID_LEN];
    session_id.copy_from_slice(&body[..UDP_SESSION_ID_LEN]);
    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&body[UDP_SESSION_ID_LEN..PREFIX]);
    let packet_id = u64::from_be_bytes(packet_id_bytes);

    finish_body(&body[PREFIX..], session_id, packet_id, direction)
}

fn open_body(
    method: Shadowsocks2022Method,
    subkey: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, UdpPacketError> {
    // The separate header is the only thing that separates a packet from a
    // random 16-byte prefix, and it is not authenticated on its own; the body
    // tag is what proves the session ID really did produce this subkey.
    crate::transport::shadowsocks2022::open(method, subkey, nonce, b"", ciphertext)
        .map_err(UdpPacketError::from)
}

fn finish_body(
    body: &[u8],
    session_id: [u8; UDP_SESSION_ID_LEN],
    packet_id: u64,
    direction: UdpDirection,
) -> Result<OpenedPacket, UdpPacketError> {
    let (header, payload) = parse_main_header(body, direction)?;
    Ok(OpenedPacket { session_id, packet_id, header, payload: payload.to_vec() })
}

// ---- session sender (section 3.2.2) --------------------------------------

/// Client-side state for one UDP relay session: the session ID and the packet
/// counter that starts at zero.
///
/// Holds no key material. The pre-shared key is passed per call rather than
/// retained, so there is no secret sitting in a long-lived struct for the
/// lifetime of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSender {
    session_id: [u8; UDP_SESSION_ID_LEN],
    next_packet_id: u64,
}

impl UdpSender {
    /// Starts a session with a caller-chosen ID. The ID must be unpredictable:
    /// it is the salt for the session subkey, and an attacker who can guess it
    /// can derive the subkey and forge packets.
    pub fn with_session_id(session_id: [u8; UDP_SESSION_ID_LEN]) -> Self {
        Self { session_id, next_packet_id: 0 }
    }

    /// Starts a session with a session ID drawn from the OS CSPRNG, which is
    /// what the specification requires ("the client generates a new random
    /// session ID").
    pub fn random() -> Result<Self, UdpPacketError> {
        let raw = crate::secure_random_bytes(UDP_SESSION_ID_LEN)
            .ok_or(UdpPacketError::PacketIdExhausted)?;
        let mut session_id = [0u8; UDP_SESSION_ID_LEN];
        session_id.copy_from_slice(&raw);
        Ok(Self::with_session_id(session_id))
    }

    pub fn session_id(&self) -> [u8; UDP_SESSION_ID_LEN] {
        self.session_id
    }

    /// Seals one client-to-server packet and advances the counter.
    ///
    /// Fails rather than wrapping at [`u64::MAX`]: reusing a packet ID reuses
    /// the body nonce, and with it both confidentiality and authenticity, for
    /// the rest of the session's life.
    pub fn seal(
        &mut self,
        method: Shadowsocks2022Method,
        psk: &[u8],
        now: u64,
        padding: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        let packet_id = self.take_packet_id()?;
        let body = build_client_body(now, padding, payload)?;
        seal_packet(method, psk, &self.session_id, packet_id, &body)
    }

    /// Seals one server-to-client packet on a **server** session. The server
    /// chooses its own session ID and echoes the client's, section 3.2.2.
    pub fn seal_response(
        &mut self,
        method: Shadowsocks2022Method,
        psk: &[u8],
        now: u64,
        client_session_id: &[u8; UDP_SESSION_ID_LEN],
        padding: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        validate_server_session_id(&self.session_id, client_session_id)?;
        let packet_id = self.take_packet_id()?;
        let body = build_server_body(now, client_session_id, padding, payload)?;
        seal_packet(method, psk, &self.session_id, packet_id, &body)
    }

    /// The ChaCha counterpart of [`UdpSender::seal`], section 4.1: a fresh
    /// random nonce per packet and no subkey derivation. The packet ID still
    /// advances, because the same sliding window filter applies.
    pub fn seal_chacha(
        &mut self,
        psk: &[u8],
        now: u64,
        padding: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        let packet_id = self.take_packet_id()?;
        let main = build_client_body(now, padding, payload)?;
        self.chacha_seal(psk, packet_id, &main)
    }

    /// The ChaCha counterpart of [`UdpSender::seal_response`]: section 4.1's
    /// server-to-client header, `server session ID(8) | server packet ID(u64be)`
    /// followed by the main header, which itself names the client session.
    ///
    /// This existed as a decoder only. [`open_packet_xchacha`] expects a
    /// server-to-client layout that nothing in the crate could produce, so a
    /// server running the ChaCha method could open a client's datagram and then
    /// had no way to answer it.
    pub fn seal_response_chacha(
        &mut self,
        psk: &[u8],
        now: u64,
        client_session_id: &[u8; UDP_SESSION_ID_LEN],
        padding: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        validate_server_session_id(&self.session_id, client_session_id)?;
        let packet_id = self.take_packet_id()?;
        let main = build_server_body(now, client_session_id, padding, payload)?;
        self.chacha_seal(psk, packet_id, &main)
    }

    /// Section 4.1: `packet := random nonce(24) || XChaCha(psk, nonce, body)`
    /// where `body := session ID(8) || packet ID(u64be) || main header`.
    ///
    /// Both directions share this framing and differ only in the main header
    /// the caller has already built, which is why the response path does not
    /// re-derive one here.
    fn chacha_seal(
        &self,
        psk: &[u8],
        packet_id: u64,
        main_header: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        let mut body = Vec::with_capacity(UDP_SESSION_ID_LEN + 8 + main_header.len());
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.extend_from_slice(main_header);
        let nonce = random_xchacha_nonce()?;
        seal_packet_xchacha(psk, &nonce, &body)
    }

    fn take_packet_id(&mut self) -> Result<u64, UdpPacketError> {
        let id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.checked_add(1).ok_or(
            // Only reachable at u64::MAX; the id itself is still valid, the
            // *next* one would wrap, so the session is finished.
            UdpPacketError::PacketIdExhausted,
        )?;
        Ok(id)
    }
}

/// A cryptographically random XChaCha nonce for section 4.1.
pub fn random_xchacha_nonce() -> Result<[u8; XCHACHA_NONCE_LEN], UdpPacketError> {
    let raw =
        crate::secure_random_bytes(XCHACHA_NONCE_LEN).ok_or(UdpPacketError::PacketIdExhausted)?;
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce.copy_from_slice(&raw);
    Ok(nonce)
}

/// Section 3.2.2: "Servers MUST not use client session IDs as server session
/// IDs."
///
/// If it were allowed, a server-to-client packet's type byte would be the only
/// thing distinguishing it from a client-to-server packet on the same session,
/// and a server session would inherit the client's replay window.
pub fn validate_server_session_id(
    server_session_id: &[u8; UDP_SESSION_ID_LEN],
    client_session_id: &[u8; UDP_SESSION_ID_LEN],
) -> Result<(), UdpPacketError> {
    if server_session_id == client_session_id {
        return Err(UdpPacketError::ServerSessionReusesClientSession);
    }
    Ok(())
}

// ---- session receiver + replay protection (section 3.2.4) -----------------

/// Server-side state for one UDP relay session.
///
/// Bundles the session ID, the expected direction, and the sliding window, so
/// that decrypt -> validate -> commit is one call. Section 3.2.4 forbids
/// updating the window before header validation; making the sequence a single
/// API is the only way to guarantee no caller reorders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpReceiver {
    session_id: [u8; UDP_SESSION_ID_LEN],
    direction: UdpDirection,
    client_session_id: Option<[u8; UDP_SESSION_ID_LEN]>,
    window: PacketIdWindow,
}

impl UdpReceiver {
    /// A server session, which receives client-to-server packets. The ID it is
    /// given is the **client's** session ID - section 3.2.2 has servers route on
    /// the client session ID, so that is the name a received packet is checked
    /// against. A server answers on a session of its own, built separately.
    pub fn server_side(client_session_id: [u8; UDP_SESSION_ID_LEN]) -> Self {
        Self {
            session_id: client_session_id,
            direction: UdpDirection::ClientToServer,
            client_session_id: None,
            window: PacketIdWindow::new(),
        }
    }

    /// A client session tracking one server's replies. Every packet it accepts
    /// must echo `client_session_id`, section 3.2.3.
    pub fn client_side(
        server_session_id: [u8; UDP_SESSION_ID_LEN],
        client_session_id: [u8; UDP_SESSION_ID_LEN],
    ) -> Self {
        Self {
            session_id: server_session_id,
            direction: UdpDirection::ServerToClient,
            client_session_id: Some(client_session_id),
            window: PacketIdWindow::new(),
        }
    }

    pub fn session_id(&self) -> [u8; UDP_SESSION_ID_LEN] {
        self.session_id
    }

    pub fn window(&self) -> &PacketIdWindow {
        &self.window
    }

    /// Authenticates, validates and commits one packet, in that order.
    ///
    /// Returns the bytes after the main header's padding (the SOCKS5 address
    /// followed by the payload). The replay window is advanced only once every
    /// check has passed, so an attacker cannot burn packet IDs with forged or
    /// stale packets.
    pub fn open(
        &mut self,
        method: Shadowsocks2022Method,
        psk: &[u8],
        now: u64,
        wire: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        let opened = open_packet(method, psk, self.direction, wire)?;
        self.commit(opened, now)
    }

    /// The ChaCha counterpart of [`UdpReceiver::open`].
    pub fn open_chacha(
        &mut self,
        psk: &[u8],
        now: u64,
        wire: &[u8],
    ) -> Result<Vec<u8>, UdpPacketError> {
        let opened = open_packet_xchacha(psk, self.direction, wire)?;
        self.commit(opened, now)
    }

    fn commit(&mut self, opened: OpenedPacket, now: u64) -> Result<Vec<u8>, UdpPacketError> {
        if opened.session_id != self.session_id {
            // A packet for another session. The caller routes by session ID;
            // reaching here means the routing was wrong, and it is not a
            // replay this session should record.
            return Err(UdpPacketError::ClientSessionMismatch);
        }
        if opened.header.direction != self.direction {
            return Err(UdpPacketError::WrongDirection);
        }
        if self.client_session_id.is_some()
            && opened.header.client_session_id != self.client_session_id
        {
            return Err(UdpPacketError::ClientSessionMismatch);
        }
        check_timestamp(opened.header.timestamp, now)
            .map_err(|_| UdpPacketError::StaleTimestamp)?;
        // Only now: every check has passed, so this packet may move the window.
        if !self.window.accept(opened.packet_id) {
            return Err(UdpPacketError::ReplayedPacket);
        }
        Ok(opened.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Obvious placeholder material, never a credential-shaped literal.
    fn psk_for(m: Shadowsocks2022Method) -> Vec<u8> {
        (0..m.psk_len() as u8).collect()
    }

    fn session_id() -> [u8; UDP_SESSION_ID_LEN] {
        [0x11u8; UDP_SESSION_ID_LEN]
    }

    // ---- packet ID window -----------------------------------------------

    #[test]
    fn window_accepts_the_first_id_and_rejects_its_replay() {
        let mut w = PacketIdWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0), "an exact replay must be refused");
        assert_eq!(w.highest(), Some(0));
    }

    #[test]
    fn window_accepts_in_order_and_rejects_a_replayed_tail() {
        let mut w = PacketIdWindow::new();
        for id in 0..8u64 {
            assert!(w.accept(id));
        }
        for id in 0..8u64 {
            assert!(!w.accept(id), "id {id} was replayed");
        }
        assert!(w.accept(8));
    }

    #[test]
    fn window_tolerates_reordering_within_the_window() {
        let mut w = PacketIdWindow::new();
        assert!(w.accept(10));
        // Arriving out of order inside the window is normal on a lossy path.
        assert!(w.accept(9));
        assert!(w.accept(7));
        assert!(!w.accept(9), "but only once");
        assert_eq!(w.highest(), Some(10));
    }

    #[test]
    fn window_rejects_ids_that_have_fallen_out_of_it() {
        let mut w = PacketIdWindow::new();
        w.accept(1000);
        // A 64-bit bitmap covers deltas 0..=63, so 937 is the lowest ID the
        // window can still represent and 936 is already out of it.
        assert!(w.accept(937), "id 937 is delta 63, the lowest still representable");
        assert!(!w.accept(936), "id 936 is delta 64 and has fallen out of the window");
        assert!(!w.accept(0), "and nothing older comes back");
    }

    // ---- main header ----------------------------------------------------

    #[test]
    fn client_body_round_trips_through_the_main_header() {
        let body = build_client_body(1_700_000_000, &[0xAA, 0xBB], b"address+payload").unwrap();
        let (hdr, rest) = parse_main_header(&body, UdpDirection::ClientToServer).unwrap();
        assert_eq!(hdr.timestamp, 1_700_000_000);
        assert_eq!(hdr.padding, vec![0xAA, 0xBB]);
        assert_eq!(rest, b"address+payload");
        assert!(hdr.client_session_id.is_none(), "client packets carry no session echo");
    }

    #[test]
    fn server_body_carries_and_checks_the_client_session_echo() {
        let client_sid = [0x22u8; UDP_SESSION_ID_LEN];
        let body = build_server_body(1_700_000_000, &client_sid, b"", b"reply").unwrap();
        let (hdr, rest) = parse_main_header(&body, UdpDirection::ServerToClient).unwrap();
        assert_eq!(hdr.client_session_id, Some(client_sid));
        assert_eq!(rest, b"reply");
        assert_eq!(body.len(), MAIN_HEADER_LEN_SERVER + 5);
    }

    #[test]
    fn a_server_packet_is_refused_where_a_client_packet_is_expected() {
        let client_sid = [0x22u8; UDP_SESSION_ID_LEN];
        let body = build_server_body(1_700_000_000, &client_sid, b"", b"x").unwrap();
        // The type byte alone must be enough to refuse it, before any length
        // arithmetic reads it as a client header.
        assert_eq!(
            parse_main_header(&body, UdpDirection::ClientToServer).unwrap_err(),
            UdpPacketError::WrongDirection
        );
    }

    #[test]
    fn padding_longer_than_the_body_is_refused() {
        let mut body = build_client_body(1_700_000_000, b"", b"x").unwrap();
        // Claim 0xFFFF padding bytes in a body that has none.
        body[9] = 0xFF;
        body[10] = 0xFF;
        assert_eq!(
            parse_main_header(&body, UdpDirection::ClientToServer).unwrap_err(),
            UdpPacketError::PaddingOverflowsBody
        );
    }

    // ---- session id rule (section 3.2.2) --------------------------------

    #[test]
    fn a_server_session_may_not_reuse_a_client_session_id() {
        let sid = [0x33u8; UDP_SESSION_ID_LEN];
        assert_eq!(
            validate_server_session_id(&sid, &sid).unwrap_err(),
            UdpPacketError::ServerSessionReusesClientSession
        );
        assert!(validate_server_session_id(&[0x34u8; UDP_SESSION_ID_LEN], &sid).is_ok());
    }

    // ---- packet layer ---------------------------------------------------

    const AES_METHODS: [Shadowsocks2022Method; 2] =
        [Shadowsocks2022Method::Aes128Gcm, Shadowsocks2022Method::Aes256Gcm];

    #[test]
    fn aes_packets_round_trip_for_both_key_sizes() {
        for m in AES_METHODS {
            let psk = psk_for(m);
            let mut sender = UdpSender::with_session_id(session_id());
            let mut receiver = UdpReceiver::server_side(session_id());
            for id in 0..4u64 {
                let wire = sender.seal(m, &psk, 1_700_000_000, b"pad", b"payload").unwrap();
                assert_eq!(
                    wire.len(),
                    UDP_SEPARATE_HEADER_LEN + MAIN_HEADER_LEN_CLIENT + 3 + 7 + UDP_TAG_LEN,
                    "{m:?} packet has the wrong total length"
                );
                assert_eq!(receiver.open(m, &psk, 1_700_000_000, &wire).unwrap(), b"payload");
                let _ = id;
            }
            assert_eq!(receiver.window().highest(), Some(3));
        }
    }

    #[test]
    fn packet_ids_are_counted_from_zero_and_increase() {
        for m in AES_METHODS {
            let psk = psk_for(m);
            let mut sender = UdpSender::with_session_id(session_id());
            let body = build_client_body(1_700_000_000, b"", b"p").unwrap();
            // Decrypting each packet's separate header is the only way to see
            // the ID, since the header is what carries it.
            let first = seal_packet(m, &psk, &sender.session_id(), 0, &body).unwrap();
            let second = seal_packet(m, &psk, &sender.session_id(), 1, &body).unwrap();
            assert_ne!(first, second);
            let _ = sender.seal(m, &psk, 1_700_000_000, b"", b"p").unwrap();
        }
    }

    #[test]
    fn a_replayed_packet_is_refused_and_does_not_move_the_window() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let mut sender = UdpSender::with_session_id(session_id());
        let mut receiver = UdpReceiver::server_side(session_id());
        let first = sender.seal(m, &psk, 1_700_000_000, b"", b"one").unwrap();
        let second = sender.seal(m, &psk, 1_700_000_000, b"", b"two").unwrap();
        assert_eq!(receiver.open(m, &psk, 1_700_000_000, &first).unwrap(), b"one");
        assert_eq!(receiver.open(m, &psk, 1_700_000_000, &second).unwrap(), b"two");
        assert_eq!(receiver.window().highest(), Some(1));

        assert_eq!(
            receiver.open(m, &psk, 1_700_000_000, &first).unwrap_err(),
            UdpPacketError::ReplayedPacket
        );
        assert_eq!(receiver.window().highest(), Some(1), "a replay must not advance the window");
    }

    /// Section 3.2.4: "the sliding window state MUST NOT be updated before
    /// successful header validation". A packet that authenticates but fails the
    /// timestamp check must leave the window exactly where it was, or an
    /// attacker could push the highest ID forward and lock out real traffic.
    #[test]
    fn a_stale_packet_does_not_advance_the_window() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let mut sender = UdpSender::with_session_id(session_id());
        let mut receiver = UdpReceiver::server_side(session_id());

        let fresh = sender.seal(m, &psk, 1_700_000_000, b"", b"one").unwrap();
        assert_eq!(receiver.open(m, &psk, 1_700_000_000, &fresh).unwrap(), b"one");
        assert_eq!(receiver.window().highest(), Some(0));

        // A high packet ID carrying a timestamp well outside the window.
        let stale_body = build_client_body(1_600_000_000, b"", b"two").unwrap();
        let stale = seal_packet(m, &psk, &session_id(), 5000, &stale_body).unwrap();
        assert_eq!(
            receiver.open(m, &psk, 1_700_000_000, &stale).unwrap_err(),
            UdpPacketError::StaleTimestamp
        );
        assert_eq!(
            receiver.window().highest(),
            Some(0),
            "a stale packet must not advance the sliding window"
        );
        // And the session still accepts the next legitimate packet.
        let next = sender.seal(m, &psk, 1_700_000_000, b"", b"three").unwrap();
        assert_eq!(receiver.open(m, &psk, 1_700_000_000, &next).unwrap(), b"three");
    }

    #[test]
    fn a_future_timestamp_is_also_a_replay() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let mut sender = UdpSender::with_session_id(session_id());
        let mut receiver = UdpReceiver::server_side(session_id());
        let wire = sender.seal(m, &psk, 1_700_000_000 + 600, b"", b"x").unwrap();
        assert_eq!(
            receiver.open(m, &psk, 1_700_000_000, &wire).unwrap_err(),
            UdpPacketError::StaleTimestamp
        );
    }

    #[test]
    fn a_packet_for_another_session_is_refused() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let mut sender = UdpSender::with_session_id([0x77u8; UDP_SESSION_ID_LEN]);
        let mut receiver = UdpReceiver::server_side([0x88u8; UDP_SESSION_ID_LEN]);
        let wire = sender.seal(m, &psk, 1_700_000_000, b"", b"x").unwrap();
        assert_eq!(
            receiver.open(m, &psk, 1_700_000_000, &wire).unwrap_err(),
            UdpPacketError::ClientSessionMismatch
        );
        assert_eq!(receiver.window().highest(), None);
    }

    #[test]
    fn tampering_with_any_byte_of_a_packet_is_refused() {
        for m in AES_METHODS {
            let psk = psk_for(m);
            let mut sender = UdpSender::with_session_id(session_id());
            let wire = sender.seal(m, &psk, 1_700_000_000, b"", b"payload").unwrap();
            for idx in 0..wire.len() {
                let mut bad = wire.clone();
                bad[idx] ^= 0x01;
                assert!(
                    UdpReceiver::server_side(session_id())
                        .open(m, &psk, 1_700_000_000, &bad)
                        .is_err(),
                    "{m:?} accepted a flipped byte at {idx}"
                );
            }
        }
    }

    #[test]
    fn a_truncated_packet_is_refused_not_panicking() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let mut sender = UdpSender::with_session_id(session_id());
        let wire = sender.seal(m, &psk, 1_700_000_000, b"", b"payload").unwrap();
        for len in 0..wire.len() {
            assert!(UdpReceiver::server_side(session_id())
                .open(m, &psk, 1_700_000_000, &wire[..len])
                .is_err());
        }
    }

    #[test]
    fn chacha_packets_round_trip_and_use_the_psk_directly() {
        let psk = psk_for(Shadowsocks2022Method::ChaCha20Poly1305);
        let mut sender = UdpSender::with_session_id(session_id());
        let mut receiver = UdpReceiver::server_side(session_id());
        let wire = sender.seal_chacha(&psk, 1_700_000_000, b"", b"payload").unwrap();
        assert_eq!(wire.len(), XCHACHA_NONCE_LEN + UDP_SESSION_ID_LEN + 8 + 11 + 7 + UDP_TAG_LEN);
        assert_eq!(receiver.open_chacha(&psk, 1_700_000_000, &wire).unwrap(), b"payload");
        // A replay is still refused by the same window.
        assert_eq!(
            receiver.open_chacha(&psk, 1_700_000_000, &wire).unwrap_err(),
            UdpPacketError::ReplayedPacket
        );
    }

    #[test]
    fn chacha_refuses_to_use_the_aes_separate_header_path() {
        let psk = psk_for(Shadowsocks2022Method::ChaCha20Poly1305);
        assert!(seal_packet(
            Shadowsocks2022Method::ChaCha20Poly1305,
            &psk,
            &session_id(),
            0,
            b"body"
        )
        .is_err());
    }

    #[test]
    fn chacha_server_and_client_ends_agree_on_a_full_exchange() {
        // Section 4.1's server-to-client header carries the server's own
        // session/packet IDs ahead of the main header. This exchange only
        // became possible when the encoder for that layout was added.
        let psk = psk_for(Shadowsocks2022Method::ChaCha20Poly1305);
        let client_sid = [0x01u8; UDP_SESSION_ID_LEN];
        let server_sid = [0x02u8; UDP_SESSION_ID_LEN];

        let mut client = UdpSender::with_session_id(client_sid);
        let mut client_rx = UdpReceiver::client_side(server_sid, client_sid);
        let mut server_rx = UdpReceiver::server_side(client_sid);
        let mut server = UdpSender::with_session_id(server_sid);

        let request = client.seal_chacha(&psk, 1_700_000_000, b"pad", b"query").unwrap();
        // 24 + (8 + 8 + 11 + 3 + 5) + 16
        assert_eq!(
            request.len(),
            XCHACHA_NONCE_LEN + UDP_SESSION_ID_LEN + 8 + 11 + 3 + 5 + UDP_TAG_LEN
        );
        assert_eq!(server_rx.open_chacha(&psk, 1_700_000_000, &request).unwrap(), b"query");

        let reply =
            server.seal_response_chacha(&psk, 1_700_000_000, &client_sid, b"", b"answer").unwrap();
        assert_eq!(
            reply.len(),
            // 24 + (8 + 8 + 19 + 6) + 16
            XCHACHA_NONCE_LEN + UDP_SESSION_ID_LEN + 8 + 19 + 6 + UDP_TAG_LEN
        );
        assert_eq!(client_rx.open_chacha(&psk, 1_700_000_000, &reply).unwrap(), b"answer");

        // A reply naming a different client session is refused, and the window
        // does not move.
        let other_client = [0x09u8; UDP_SESSION_ID_LEN];
        let mut server2 = UdpSender::with_session_id([0x0Au8; UDP_SESSION_ID_LEN]);
        let wrong =
            server2.seal_response_chacha(&psk, 1_700_000_000, &other_client, b"", b"x").unwrap();
        assert_eq!(
            client_rx.open_chacha(&psk, 1_700_000_000, &wrong).unwrap_err(),
            UdpPacketError::ClientSessionMismatch
        );
        assert_eq!(client_rx.window().highest(), Some(0));
    }

    /// A server session ID equal to the client's is refused in both
    /// constructions, not just the AES one.
    #[test]
    fn chacha_seals_refuse_to_reuse_a_client_session_id() {
        let psk = psk_for(Shadowsocks2022Method::ChaCha20Poly1305);
        let sid = [0x33u8; UDP_SESSION_ID_LEN];
        let mut sender = UdpSender::with_session_id(sid);
        assert_eq!(
            sender.seal_response_chacha(&psk, 1_700_000_000, &sid, b"", b"x").unwrap_err(),
            UdpPacketError::ServerSessionReusesClientSession
        );
        // A refused response must not have consumed a packet ID.
        assert_eq!(sender.next_packet_id, 0);
    }

    #[test]
    fn server_and_client_ends_agree_on_a_full_exchange() {
        let m = Shadowsocks2022Method::Aes256Gcm;
        let psk = psk_for(m);
        let client_sid = [0x01u8; UDP_SESSION_ID_LEN];
        let server_sid = [0x02u8; UDP_SESSION_ID_LEN];
        validate_server_session_id(&server_sid, &client_sid).expect("distinct ids");

        let mut client = UdpSender::with_session_id(client_sid);
        let mut client_rx = UdpReceiver::client_side(server_sid, client_sid);
        let mut server_rx = UdpReceiver::server_side(client_sid);
        let mut server = UdpSender::with_session_id(server_sid);

        let request = client.seal(m, &psk, 1_700_000_000, b"pad", b"query").unwrap();
        assert_eq!(server_rx.open(m, &psk, 1_700_000_000, &request).unwrap(), b"query");

        let reply =
            server.seal_response(m, &psk, 1_700_000_000, &client_sid, b"", b"answer").unwrap();
        assert_eq!(client_rx.open(m, &psk, 1_700_000_000, &reply).unwrap(), b"answer");

        // A reply naming the wrong client session is refused.
        let other_client = [0x09u8; UDP_SESSION_ID_LEN];
        let mut server2 = UdpSender::with_session_id([0x0Au8; UDP_SESSION_ID_LEN]);
        let wrong =
            server2.seal_response(m, &psk, 1_700_000_000, &other_client, b"", b"x").unwrap();
        assert_eq!(
            client_rx.open(m, &psk, 1_700_000_000, &wrong).unwrap_err(),
            UdpPacketError::ClientSessionMismatch
        );
    }

    #[test]
    fn random_session_ids_and_nonces_differ() {
        assert_ne!(UdpSender::random().expect("entropy").session_id(), [0u8; 8]);
        let a = random_xchacha_nonce().expect("entropy");
        let b = random_xchacha_nonce().expect("entropy");
        assert_ne!(a, b);
        let _ = a;
        let _ = b;
    }
}
