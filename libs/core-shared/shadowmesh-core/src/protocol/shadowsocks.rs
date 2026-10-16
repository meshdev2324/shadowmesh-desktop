//! Shadowsocks AEAD (SIP007) + Shadowsocks-2022 (SIP022-family) Implementation.
//!
//! Implementation Source:
//! - Specification: Shadowsocks AEAD (SIP007); Shadowsocks 2022 edition
//!   (SIP022-family public specification)
//! - RFC: RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF), BLAKE3 (public spec)
//! - Relevant Sections: Key Derivation (SIP007: HKDF-SHA1; 2022: BLAKE3
//!   derive_key), AEAD Chunk Framing, 2022 fixed-length header + timestamps
//! - Security Considerations: Mandatory salt uniqueness, subkey derivation,
//!   replay rejection (2022), Zeroize.
//!
//! This is an independent implementation authored for ShadowMesh Core.

use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use ring::aead::{
    Aad, BoundKey, LessSafeKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
    AES_256_GCM, CHACHA20_POLY1305,
};
use sha1::Sha1;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

pub const MAX_CHUNK_SIZE: usize = 0x3FFF; // 16383 bytes
pub const LENGTH_SIZE: usize = 2;
pub const TAG_SIZE: usize = 16;

// The 2022-edition skew window is NOT restated here. It is
// `ss2022_stream::MAX_TIME_SKEW_SECS`, and that is the value the stream's reader
// actually applies. A second constant beside it, in seconds, describing a
// millisecond-valued header that no longer exists, is exactly the kind of
// duplicate that let the two disagree about the wire format in the first place.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    Aes256Gcm,
    ChaCha20Poly1305,
    /// `2022-blake3-aes-128-gcm`: BLAKE3-derived keys, a salt as long as the
    /// key, timestamped fixed-length header (replay-resistant).
    ///
    /// SIP022 section 3 marks both AES methods MUST-implement. This variant was
    /// missing while [`crate::transport::shadowsocks2022::Shadowsocks2022Method`]
    /// already modelled it, so a 16-byte-key node could not be selected here
    /// even though the transport layer believed it supported it. The two enums
    /// are now bound by `TryFrom`/`From` and a test that walks the bijection.
    Aes128Gcm2022,
    /// `2022-blake3-aes-256-gcm`: BLAKE3-derived keys, a salt as long as the
    /// key, timestamped fixed-length header (replay-resistant).
    Aes256Gcm2022,
    /// `2022-blake3-chacha20-poly1305`.
    ChaCha20Poly13052022,
}

impl ShadowsocksMethod {
    /// The SIP022 / SIP007 method name as it appears on the wire.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly13052022 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            // 2022 edition: 32-byte keys, base64 in config.
            Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022 => 32,
            Self::Aes128Gcm2022 => 16,
        }
    }

    pub fn salt_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            // 2022 edition: SIP022 section 2.2 - "The salt has the same length
            // as the pre-shared key". This was 12, which is the *nonce* length,
            // not the salt length; a 12-byte salt put on the wire is rejected
            // by every conforming peer, and it also made the derived subkey
            // disagree with theirs.
            Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022 => {
                self.key_len()
            }
        }
    }

    pub fn is_2022(&self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022)
    }

    /// The 2022-edition counterpart of this method, or `None` for the legacy
    /// SIP007 methods. The conversion is total in both directions
    /// (`TryFrom` below is its inverse), so the two enums cannot drift apart
    /// the way they had.
    pub fn as_ss2022(self) -> Option<crate::transport::shadowsocks2022::Shadowsocks2022Method> {
        use crate::transport::shadowsocks2022::Shadowsocks2022Method as M;
        match self {
            Self::Aes128Gcm2022 => Some(M::Aes128Gcm),
            Self::Aes256Gcm2022 => Some(M::Aes256Gcm),
            Self::ChaCha20Poly13052022 => Some(M::ChaCha20Poly1305),
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => None,
        }
    }

    fn ring_algorithm(&self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes128Gcm2022 => &ring::aead::AES_128_GCM,
            Self::Aes256Gcm | Self::Aes256Gcm2022 => &AES_256_GCM,
            Self::ChaCha20Poly1305 | Self::ChaCha20Poly13052022 => &CHACHA20_POLY1305,
        }
    }
}

impl TryFrom<ShadowsocksMethod> for crate::transport::shadowsocks2022::Shadowsocks2022Method {
    type Error = anyhow::Error;

    fn try_from(m: ShadowsocksMethod) -> Result<Self, Self::Error> {
        m.as_ss2022().ok_or_else(|| anyhow!("{} is not a Shadowsocks-2022 method", m.wire_name()))
    }
}

impl std::str::FromStr for ShadowsocksMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm2022),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm2022),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly13052022),
            _ => Err(anyhow!("Unsupported shadowsocks method: {}", s)),
        }
    }
}

pub struct ShadowsocksNonceSequence {
    nonce: [u8; 12],
}

impl Default for ShadowsocksNonceSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowsocksNonceSequence {
    pub fn new() -> Self {
        Self { nonce: [0u8; 12] }
    }

    fn increment(&mut self) {
        for i in 0..12 {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            }
        }
    }
}

impl NonceSequence for ShadowsocksNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let n = Nonce::try_assume_unique_for_key(&self.nonce)?;
        self.increment();
        Ok(n)
    }
}

pub struct ShadowsocksCipher {
    method: ShadowsocksMethod,
    subkey: Vec<u8>,
}

impl ShadowsocksCipher {
    /// 2022-edition constructor: parses the base64 pre-shared key and derives
    /// the session subkey. Returns Err when the wire format is wrong.
    ///
    /// The derivation is delegated to
    /// [`crate::transport::shadowsocks2022::derive_session_subkey`], which
    /// implements SIP022 section 2.2 verbatim and is pinned by the
    /// vectors computed independently from §2.2. It used to be a second, private
    /// copy here using a non-normative context string and the key material
    /// concatenated in the opposite order, which meant the 2022 stream path
    /// produced a subkey no conforming peer could reproduce. There is now
    /// exactly one 2022 subkey derivation in this crate.
    pub fn new_2022(method: ShadowsocksMethod, configured: &str, salt: &[u8]) -> Result<Self> {
        let master = crate::protocol::ss2022::parse_identity_key(configured, method.key_len())
            .map_err(anyhow::Error::msg)?;
        let subkey = crate::transport::shadowsocks2022::derive_session_subkey(
            method.try_into()?,
            &master,
            salt,
        )
        .map_err(|e| anyhow!("SS2022 session subkey derivation failed: {e}"))?;
        Ok(Self { method, subkey })
    }

    pub fn new(method: ShadowsocksMethod, password: &str, salt: &[u8]) -> Result<Self> {
        if method.is_2022() {
            if salt.len() != method.salt_len() {
                return Err(anyhow!(
                    "2022-edition salt must be exactly {} bytes (got {})",
                    method.salt_len(),
                    salt.len()
                ));
            }
            return Self::new_2022(method, password, salt);
        }

        let mut master_key = Vec::with_capacity(method.key_len());
        let mut hasher = Md5::new();
        hasher.update(password.as_bytes());
        let mut m = hasher.finalize().to_vec();
        master_key.extend_from_slice(&m);

        while master_key.len() < method.key_len() {
            let mut hasher = Md5::new();
            hasher.update(&m);
            hasher.update(password.as_bytes());
            m = hasher.finalize().to_vec();
            master_key.extend_from_slice(&m);
        }
        master_key.truncate(method.key_len());

        let hk = Hkdf::<Sha1>::new(Some(salt), &master_key);
        let mut subkey = vec![0u8; method.key_len()];
        hk.expand(b"ss-subkey", &mut subkey).map_err(|_| anyhow!("HKDF expand failed"))?;

        master_key.zeroize();

        Ok(Self { method, subkey })
    }

    /// SHA-256 digest of the derived subkey, for key-derivation verification.
    ///
    /// Deliberately does not expose the raw subkey: callers (tests, health
    /// checks) compare digests to assert KDF determinism and salt sensitivity
    /// without leaking key material into logs or assertions.
    pub fn subkey_digest(&self) -> [u8; 32] {
        use sha2::Sha256;
        let mut h = Sha256::new();
        h.update(&self.subkey);
        h.finalize().into()
    }

    pub fn sealing_key(mut self) -> Result<SealingKey<ShadowsocksNonceSequence>> {
        let unbound = UnboundKey::new(self.method.ring_algorithm(), &self.subkey);
        // Zeroize the subkey unconditionally: on success it lives on inside the
        // UnboundKey, on failure it must not linger in this struct.
        self.subkey.zeroize();
        let unbound =
            unbound.map_err(|_| anyhow!("unsupported AEAD key length for sealing key"))?;
        Ok(SealingKey::new(unbound, ShadowsocksNonceSequence::new()))
    }

    pub fn opening_key(mut self) -> Result<OpeningKey<ShadowsocksNonceSequence>> {
        let unbound = UnboundKey::new(self.method.ring_algorithm(), &self.subkey);
        self.subkey.zeroize();
        let unbound =
            unbound.map_err(|_| anyhow!("unsupported AEAD key length for opening key"))?;
        Ok(OpeningKey::new(unbound, ShadowsocksNonceSequence::new()))
    }

    /// Encrypts a single UDP packet as per SIP007 (Shadowsocks AEAD-2017).
    ///
    /// Wire layout, per the SIP007 UDP section:
    ///
    /// ```text
    /// [salt][ AEAD(subkey, nonce = 12 zero bytes, plaintext) || tag ]
    /// ```
    ///
    /// There is deliberately **no length chunk**. That section reads: "Each UDP
    /// packet is encrypted/decrypted independently, using the derived subkey
    /// and a nonce with all zero bytes." The length chunk belongs to the TCP
    /// chunk format only; a datagram is already delimited, and a 16-byte AEAD
    /// tag is an unambiguous end marker. Adding a length field here would break
    /// interoperability with every conforming SIP007 peer, which is precisely
    /// what this function exists to serve.
    ///
    /// The salt is CSPRNG-generated per packet, which is what makes the
    /// all-zero nonce safe: every packet has its own subkey, so no nonce is
    /// ever reused under one key.
    ///
    /// # 2022-edition methods are refused
    ///
    /// SIP022 replaced this format wholesale (sections 3.2 and 4.1): the two
    /// AES methods use a 16-byte AES-block-encrypted separate header plus a
    /// session-subkeyed AEAD body, and the ChaCha method uses a random
    /// 24-byte XChaCha20-Poly1305 nonce with no subkey at all. Neither is this
    /// layout. Emitting SIP007 framing for a 2022 method would produce a packet
    /// that is well-formed, self-consistent, and undecryptable by anything else
    /// — the exact failure mode this function used to have.
    ///
    /// It now fails closed. Use [`crate::protocol::ss2022::UdpSender`] and
    /// [`crate::protocol::ss2022::UdpReceiver`] instead.
    pub fn encrypt_udp(
        method: ShadowsocksMethod,
        password: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if method.is_2022() {
            return Err(anyhow!(
                "{} UDP is not SIP007 single-packet framing; \
                 use protocol::ss2022::UdpSender/UdpReceiver (SIP022 sections 3.2 / 4.1)",
                method.wire_name()
            ));
        }
        let salt_len = method.salt_len();
        // CSPRNG salt (OS entropy): SIP007 requires unique unpredictable
        // salts per session — a weaker generator would be a protocol break.
        let salt = crate::secure_random_bytes(salt_len)
            .ok_or_else(|| anyhow!("OS entropy source failed for SS salt"))?;

        let cipher = Self::new(method, password, &salt)?;
        let unbound = UnboundKey::new(method.ring_algorithm(), &cipher.subkey)
            .map_err(|_| anyhow!("UDP AEAD key init failed"))?;
        let sealing_key = LessSafeKey::new(unbound);

        let mut out = plaintext.to_vec();
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);

        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut out)
            .map_err(|_| anyhow!("UDP encryption failed"))?;

        let mut result = salt;
        result.extend_from_slice(&out);
        Ok(result)
    }

    /// Decrypts a single SIP007 UDP packet. The exact inverse of
    /// [`Self::encrypt_udp`], and refuses 2022-edition methods for the same
    /// reason.
    pub fn decrypt_udp(
        method: ShadowsocksMethod,
        password: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if method.is_2022() {
            return Err(anyhow!(
                "{} UDP is not SIP007 single-packet framing; \
                 use protocol::ss2022::UdpReceiver (SIP022 sections 3.2 / 4.1)",
                method.wire_name()
            ));
        }
        let salt_len = method.salt_len();
        if ciphertext.len() < salt_len + TAG_SIZE {
            return Err(anyhow!("UDP packet too short"));
        }

        let salt = &ciphertext[..salt_len];
        let cipher = Self::new(method, password, salt)?;
        let unbound = UnboundKey::new(method.ring_algorithm(), &cipher.subkey)
            .map_err(|_| anyhow!("UDP AEAD key init failed"))?;
        let opening_key = LessSafeKey::new(unbound);

        let mut out = ciphertext[salt_len..].to_vec();
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);

        let decrypted = opening_key
            .open_in_place(nonce, Aad::empty(), &mut out)
            .map_err(|_| anyhow!("UDP decryption failed"))?;

        Ok(decrypted.to_vec())
    }
}

/// Length-hiding padding policy (RFC-012 G5).
///
/// Re-exported from [`crate::protocol::padding`], which owns the contract for
/// every protocol G5 names — VMess uses the same policy, writer and reader.
/// This path is kept because it is the one the transport layer and the config
/// settings already name.
pub use crate::protocol::padding::{PaddingMode, MAX_PAD_BYTES, MAX_PAD_COST};

use crate::protocol::padding::{draw_pad_len, strip_padding, write_pad_tail};
use crate::protocol::ss2022_stream::{self, HeaderError};

use ss2022_stream::{socks5_addr_len, MAX_SOCKS5_ADDR_LEN};

/// How many further bytes of `buf` are needed before the SOCKS5 address at the
/// head of `staged ++ buf` is complete, or `None` while that is not yet knowable.
///
/// SIP022 section 3.1.2 puts the target address in the variable-length header
/// chunk, which is a **standalone AEAD chunk**. The writer therefore has to know
/// where the address ends before it can seal that chunk, and nothing on the wire
/// marks the boundary: the address is the head of the same buffer the caller
/// wrote. The only way to find it is to parse the ATYP.
///
/// `consumed` bytes of `buf` have already been staged, so the ATYP and (for a
/// domain) the length byte may already be sitting in `staged`.
fn ss2022_addr_needed(staged: &[u8], buf: &[u8]) -> Option<usize> {
    // At most 2 bytes of `staged` are ever needed (ATYP, then domain length).
    let have = staged.len() + buf.len();
    let atyp = *staged.first()?;
    let domain_len = if atyp == 3 {
        // The domain length is the second byte: staged if it arrived, else it is
        // the first byte of `buf`.
        match (staged.get(1), buf.first()) {
            (Some(&b), _) => Some(b),
            (None, Some(&b)) => Some(b),
            (None, None) => None,
        }
    } else {
        None
    };
    let total = socks5_addr_len(atyp, domain_len)?;
    if have >= total {
        Some(total - staged.len())
    } else {
        None
    }
}

/// Current unix time in **seconds**.
///
/// SIP022 section 3.1.1 specifies seconds for the stream header, and
/// `ss2022_stream::check_timestamp` compares it against a second-valued clock
/// with a 30-second window. The writer used to emit `as_millis`, so every
/// conformant receiver computed a skew of ~1.7e12 seconds and rejected the
/// stream as stale — a header that authenticated perfectly and was still
/// unusable.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Renders a `HeaderError` as an `io::Error` without leaking which check failed.
///
/// The opacity is deliberate and is `HeaderError`'s own documented rule: a
/// message that distinguishes "bad type byte" from "stale timestamp" is a
/// probing oracle if it ever reaches a peer.
fn header_err_to_io(_e: HeaderError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SS2022 stream header")
}

/// Appends `bytes` to `buf`.
///
/// A named function rather than a method so the 2022 writers can append to
/// `self.write_buf` while a closure holds a mutable borrow of
/// `self.sealing_key`: the borrow checker splits the borrow through a free
/// function but not through `self`.
fn this_write(buf: &mut BytesMut, bytes: &[u8]) {
    buf.extend_from_slice(bytes);
}

pub struct ShadowsocksStream<S> {
    inner: S,
    method: ShadowsocksMethod,
    /// SIP007 password / SIP022 PSK, verbatim from config. This is the
    /// long-lived secret this stream re-derives a subkey from on first read
    /// and first write, so it must outlive the handshake — and must not
    /// outlive the session. Zeroized on drop.
    password: String,
    sealing_key: Option<SealingKey<ShadowsocksNonceSequence>>,
    opening_key: Option<OpeningKey<ShadowsocksNonceSequence>>,

    // Handshake state
    write_salt_sent: bool,
    read_salt_received: bool,
    write_salt: Vec<u8>,
    read_salt: Vec<u8>,

    // Read state
    read_buf: BytesMut,
    payload_buf: BytesMut,
    remaining_payload: usize,
    reading_length: bool,

    // Write state
    write_buf: BytesMut,
    /// Chunk size of the in-flight frame whose bytes are still in `write_buf`.
    /// `Some(n)` means: drain `write_buf`, then report `Ready(Ok(n))`. Never
    /// re-encrypt a frame while a previous one is still in flight — that would
    /// duplicate the payload on the wire when `write_all` retries.
    pending_chunk_size: Option<usize>,
    encrypt_buf: Vec<u8>,
    /// 2022 edition: the salt and the stream header chunks have not gone out
    /// yet.
    ss2022_header_pending: bool,
    /// 2022 edition: which header the reader is waiting for.
    ss2022_read: Ss2022ReadState,
    /// 2022 client: SOCKS5 address bytes accepted so far but not yet long
    /// enough to seal as the variable-length header chunk. `write_all` may
    /// split the address across any number of `poll_write` calls, so these
    /// bytes are staged rather than dropped.
    ss2022_header_stage: BytesMut,
    /// Which end of a 2022 stream this is when writing. See [`StreamRole`].
    write_role: StreamRole,
    /// Which end of a 2022 stream this is when reading. Kept separate from
    /// `write_role` because the two directions of one proxied connection are
    /// opposite: the outbound opens a request and reads a response, the inbound
    /// reads a request and writes a response. A single role field could not
    /// name either of those two real shapes.
    read_role: StreamRole,
    /// RFC-012 G5: when On, every frame carries [u8 pad_len][pad] after the
    /// payload; the reader strips it after AEAD verification.
    padding: PaddingMode,
}

/// Which end of a 2022 stream this is.
///
/// Not cosmetic. A request stream and a response stream have different header
/// layouts (SIP022 section 3.1.3), and only the type byte distinguishes them,
/// so a writer that does not know which it is cannot emit a header the peer can
/// parse, and a reader that does not know which it is cannot decide what to
/// accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    /// Opens the stream. Seals a client-stream request header.
    Client,
    /// Answers the stream. Seals a server-stream response header.
    Server,
}

/// Reader position within the SIP022 section 3.1.2 header sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ss2022ReadState {
    /// Legacy SIP007 framing: straight to length/payload chunks.
    Off,
    /// Awaiting the fixed-length request header chunk.
    RequestFixed,
    /// Awaiting the variable-length request header chunk, of the given
    /// plaintext length (the SOCKS5 address).
    RequestVariable(usize),
    /// Awaiting the response header chunk.
    ResponseFixed,
    /// Awaiting the payload chunk the response header declared.
    ResponsePayload(usize),
    /// Headers done; normal length/payload chunks.
    Payload,
}

/// Outcome of one incremental fill of `read_buf` from the inner transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FillOutcome {
    /// The requested bytes are in `read_buf`.
    Filled,
    /// The inner transport has more to give but is not ready yet.
    Pending,
    /// The peer closed before the requested bytes arrived.
    Eof,
}

/// RFC-008 §5, scoped to what this type actually holds.
///
/// The stream carries the SIP007 password (or the SIP022 PSK) plus both AEAD
/// salts. Those four are the session-derived key material: the salts feed the
/// subkey derivation directly, and the password is the input that derivation
/// starts from. An attacker who reads any of them after the session ends holds
/// what is needed to impersonate the peer, which is exactly the forensic
/// exposure §5 exists to remove — core dumps, swap, and freed-but-unmapped
/// heap are all readable by anything that can read the process's address
/// space.
///
/// ## What is deliberately *not* zeroized here
///
/// * `sealing_key` / `opening_key` — `ring`'s `SealingKey`/`OpeningKey` wrap a
///   private `KeyInner` and implement neither `Zeroize` nor `Drop`; the bytes
///   are unreachable without `unsafe`, and this crate is
///   `#![forbid(unsafe_op_in_unsafe_fn)]` with no unsafe in the protocol
///   layer. Zeroizing the salts removes what is needed to *re-derive* them,
///   which is the recoverable property; erasing the key schedule itself is
///   not reachable from here.
/// * `read_buf` / `payload_buf` / `write_buf` / `encrypt_buf` — plaintext and
///   ciphertext transport buffers, not key material. `payload_buf` holds
///   decrypted application bytes that belong to the user's traffic, not to
///   the session's identity; scrubbing it would defend against nothing and
///   would cost a write to every buffer on the hot path. `encrypt_buf` is
///   ciphertext on the way to the wire, and is pre-zeroed at construction.
///
/// Every field reachable here is a plain owned buffer, which is why this can
/// be a hand-written `impl` rather than a derive: the AEAD key fields are
/// opaque third-party types, so `#[derive(Zeroize)]` would not compile.
impl<S> Zeroize for ShadowsocksStream<S> {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.write_salt.zeroize();
        self.read_salt.zeroize();
    }
}

impl<S> Drop for ShadowsocksStream<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ShadowsocksStream<S> {
    /// Stream without length-hiding padding (wire-compatible default).
    pub fn new(inner: S, method: ShadowsocksMethod, password: &str) -> Self {
        Self::with_options(inner, method, password, PaddingMode::Off)
    }

    /// Stream with explicit padding (RFC-012 G5). Padding randomizes each
    /// frame's length within [payload, payload + 255] so chunk-length
    /// correlation cannot reconstruct the plaintext's size profile.
    pub fn with_options(
        inner: S,
        method: ShadowsocksMethod,
        password: &str,
        padding: PaddingMode,
    ) -> Self {
        // CSPRNG salt (OS entropy). Sync constructor: on entropy failure the
        // zero salt forces the first AEAD key derivation to mismatch any
        // legitimate peer AND ensure_sealing_key surfaces the error — a
        // stream can never silently operate with a predictable salt.
        let write_salt = crate::secure_random_bytes(method.salt_len())
            .unwrap_or_else(|| vec![0u8; method.salt_len()]);

        Self {
            inner,
            method,
            password: password.to_string(),
            sealing_key: None,
            opening_key: None,
            write_salt_sent: false,
            read_salt_received: false,
            write_salt,
            read_salt: vec![0u8; method.salt_len()],
            read_buf: BytesMut::with_capacity(4096),
            payload_buf: BytesMut::with_capacity(4096),
            remaining_payload: 0,
            reading_length: true,
            write_buf: BytesMut::with_capacity(4096),
            pending_chunk_size: None,
            encrypt_buf: vec![0u8; MAX_CHUNK_SIZE + TAG_SIZE],
            ss2022_header_pending: method.is_2022(),
            // Read default: expect a REQUEST header. `with_role` moves this to
            // the response sequence when the caller says it is the client end.
            ss2022_read: if method.is_2022() {
                Ss2022ReadState::RequestFixed
            } else {
                Ss2022ReadState::Off
            },
            ss2022_header_stage: BytesMut::with_capacity(MAX_SOCKS5_ADDR_LEN),
            // Write default: seal a REQUEST header. See `with_role`.
            write_role: StreamRole::Client,
            read_role: StreamRole::Server,
            padding,
        }
    }

    /// Declare which end of a 2022 stream this is, for both directions at once.
    ///
    /// [`StreamRole::Client`] is the end that opens a request and reads the
    /// response to it; [`StreamRole::Server`] is the end that reads a request
    /// and answers it. The default is the request-on-write / request-on-read
    /// pairing, which is the shape a stream has before either peer has said
    /// anything; use [`Self::with_read_role`] when only one direction differs,
    /// which is the case for a relay that opens one way and answers the other.
    ///
    /// Meaningless for a legacy SIP007 method, which has no stream header; the
    /// call is accepted and ignored rather than being an error, so a caller
    /// that does not branch on the method does not have to.
    pub fn with_role(mut self, role: StreamRole) -> Self {
        self.write_role = role;
        self.read_role = match role {
            StreamRole::Client => StreamRole::Client,
            StreamRole::Server => StreamRole::Server,
        };
        self.apply_read_role();
        self
    }

    /// Declare only the read direction, for a 2022 stream.
    ///
    /// The two directions of a proxied connection are opposite — an outbound
    /// opens a request and reads the response to it — so a relay cannot express
    /// itself with one role. This sets the reader without touching the writer.
    pub fn with_read_role(mut self, role: StreamRole) -> Self {
        self.read_role = role;
        self.apply_read_role();
        self
    }

    fn apply_read_role(&mut self) {
        if !self.method.is_2022() {
            self.ss2022_read = Ss2022ReadState::Off;
            return;
        }
        self.ss2022_read = match self.read_role {
            // The client end reads a response header, which is also its first
            // length chunk.
            StreamRole::Client => Ss2022ReadState::ResponseFixed,
            StreamRole::Server => Ss2022ReadState::RequestFixed,
        };
    }

    fn ensure_sealing_key(&mut self) -> Result<()> {
        if self.sealing_key.is_none() {
            let cipher = ShadowsocksCipher::new(self.method, &self.password, &self.write_salt)?;
            self.sealing_key = Some(cipher.sealing_key()?);
        }
        Ok(())
    }

    fn ensure_opening_key(&mut self) -> Result<()> {
        if self.opening_key.is_none() {
            let cipher = ShadowsocksCipher::new(self.method, &self.password, &self.read_salt)?;
            self.opening_key = Some(cipher.opening_key()?);
        }
        Ok(())
    }

    /// Reads at least `want` more bytes from the inner transport into
    /// `read_buf`, and reports whether they arrived.
    ///
    /// The 2022 header chunks are *declared* — the fixed header says how long
    /// the variable header is, and the response header says how long its payload
    /// is — so the reader must be able to wait for an exact number of bytes
    /// across an arbitrary number of socket reads. That is what this does, and
    /// it is written here rather than assumed at each call site: a reader that
    /// cannot express "not enough bytes yet" has to either block or misparse.
    ///
    /// `Eof` means the peer closed with fewer than `want` bytes outstanding,
    /// which for every caller here is a truncated frame rather than a clean
    /// end-of-stream: these are all mid-frame positions.
    fn fill_read_buf(&mut self, cx: &mut Context<'_>, want: usize) -> FillOutcome {
        // Bounded so a peer that promises an enormous declared length cannot
        // make this allocate without limit in a single pass; the loop simply
        // runs again.
        const MAX_FILL: usize = 16 * 1024;
        let mut temp = [0u8; 4096];
        let mut filled = 0usize;
        while filled < want {
            let room = std::cmp::min(std::cmp::min(temp.len(), want - filled), MAX_FILL);
            let mut rb = ReadBuf::new(&mut temp[..room]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return FillOutcome::Eof;
                    }
                    self.read_buf.extend_from_slice(rb.filled());
                    filled += n;
                }
                // An inner error is reported by the caller's own error path;
                // treating it as Pending would spin. Propagate it as an EOF-like
                // stop and let the caller surface an invalid-frame error, which
                // is the same outcome a truncated frame produces.
                Poll::Ready(Err(_)) => return FillOutcome::Eof,
                Poll::Pending => return FillOutcome::Pending,
            }
        }
        FillOutcome::Filled
    }

    /// Seals a 2022 stream's header chunks, then reports the caller's bytes as
    /// consumed. Called from `poll_write` only while `ss2022_header_pending`.
    ///
    /// Returns `Poll::Ready(Ok(n))` where `n` is how many of `buf` were taken.
    /// For the client those are the SOCKS5 address bytes and nothing else: the
    /// address becomes the variable-length header chunk, and whatever the caller
    /// writes next becomes the first length/payload pair. For the server there
    /// is no address, so `n` is the whole buffer and the first payload is sealed
    /// behind the response header.
    fn write_2022_headers(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.write_role {
            StreamRole::Client => self.write_2022_request_headers(cx, buf),
            StreamRole::Server => self.write_2022_response_header(cx, buf),
        }
    }

    /// Client: two standalone header chunks — the fixed header, then the
    /// variable-length header carrying the SOCKS5 address.
    ///
    /// The address is the head of `buf` and nothing on the wire marks where it
    /// ends, so the boundary is sniffed from the ATYP. Until the address is
    /// whole the bytes are staged and reported consumed rather than dropped,
    /// because `write_all` may split the address across any number of
    /// `poll_write` calls.
    ///
    /// This method passes only the **address** to `ss2022_stream`, which owns
    /// the rest of the variable-length header — the padding length and the
    /// padding — and draws the padding itself. The layout is deliberately not
    /// restated here: this method's job is to find where the caller's address
    /// ends, and the header's job is to know what follows it. Two copies of the
    /// second rule is how RFC-012 §12.1's desynchronisation happened once.
    fn write_2022_request_headers(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // The ATYP byte is the whole of the address's self-description, and it
        // is the first byte the caller sent. If it is not one this code
        // implements then no boundary will ever be found, so the stream is
        // rejected here rather than after buffering without limit. Failing fast
        // matters for more than tidiness: a writer that keeps staging bytes
        // waiting for an address that cannot arrive holds the caller's
        // `write_all` forever, with no error and no progress.
        if let Some(&atyp) = self.ss2022_header_stage.first() {
            if socks5_addr_len(atyp, None).is_none() && !(atyp == 3) {
                self.ss2022_header_stage.clear();
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SS2022 request header is not a SOCKS5 address",
                )));
            }
        }

        // Take only as much as could still be part of the address.
        let take = match ss2022_addr_needed(&self.ss2022_header_stage, buf) {
            Some(n) => std::cmp::min(n, buf.len()),
            None => buf.len(),
        };
        self.ss2022_header_stage.extend_from_slice(&buf[..take]);

        // Re-measure against the staged bytes alone: once the address is
        // complete this reports the length, and no further bytes are taken from
        // the caller in this call.
        if ss2022_addr_needed(&self.ss2022_header_stage, &[]).is_none() {
            if self.ss2022_header_stage.len() > MAX_SOCKS5_ADDR_LEN {
                // Cannot still be accumulating a valid address, so no boundary
                // will ever be found. Fail closed rather than buffer forever.
                self.ss2022_header_stage.clear();
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SS2022 request header is not a SOCKS5 address",
                )));
            }
            // Push whatever is already staged (the salt) so the peer can make
            // progress, then report the staged bytes as consumed.
            return self.flush_written(cx, take);
        }

        let variable: Vec<u8> = self.ss2022_header_stage[..].to_vec();
        self.ss2022_header_stage.clear();
        self.ensure_sealing_key().map_err(io::Error::other)?;

        let sealed = {
            let key = self
                .sealing_key
                .as_mut()
                .ok_or_else(|| io::Error::other("AEAD sealing key not initialized"))?;
            // Two AEAD operations, two nonces. The closure is what makes
            // "standalone" structural rather than aspirational: the single owner
            // of the framing calls it exactly once per chunk. `variable` is the
            // SOCKS5 address; the owner appends the §3.1.3 padding length and
            // padding, and draws the padding length in 1..=256 so the whole
            // salt-and-headers burst stays inside one MTU.
            ss2022_stream::seal_request_headers_with(unix_now_secs(), &variable, |chunk| {
                let mut c = chunk.to_vec();
                match key.seal_in_place_separate_tag(Aad::empty(), &mut c) {
                    Ok(tag) => {
                        c.extend_from_slice(tag.as_ref());
                        Ok(c)
                    }
                    Err(_) => Err(HeaderError::Auth),
                }
            })
            .map_err(header_err_to_io)?
        };
        this_write(&mut self.write_buf, &sealed);
        self.ss2022_header_pending = false;

        // The address bytes the headers carry were consumed from `buf` and are
        // reported written here: they are the caller's bytes, and withholding
        // them would make `write_all` spin forever.
        self.flush_written(cx, take)
    }

    /// Server: one header chunk, which is also the first length chunk.
    ///
    /// There is nothing legal to write until a payload exists, and — unlike the
    /// client — there is no address to sniff: the server writes back proxied
    /// bytes, not a SOCKS5 address. So this buffers nothing and instead seals the
    /// payload that arrives with this very call.
    fn write_2022_response_header(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.ensure_sealing_key().map_err(io::Error::other)?;

        let pad_len = draw_pad_len(self.padding);
        let first_len = std::cmp::min(buf.len(), MAX_CHUNK_SIZE);
        // The header declares the length of the payload chunk that follows it,
        // charged exactly as a length chunk would be (see the padding note in
        // `poll_write`).
        let declared = crate::protocol::padding::padded_frame_len(first_len, pad_len, self.padding);
        if declared > u16::MAX as usize {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SS2022 response header length overflows the u16 field",
            )));
        }

        let sealed_header = {
            let key = self
                .sealing_key
                .as_mut()
                .ok_or_else(|| io::Error::other("AEAD sealing key not initialized"))?;
            // Section 3.1.3: the response echoes the request salt, binding the
            // response to the request that caused it. On this end that is the
            // salt read from the peer; echoing our own would emit a header the
            // client could not bind to anything.
            let echo: Vec<u8> = self.read_salt.clone();
            ss2022_stream::seal_response_header_with(
                unix_now_secs(),
                &echo,
                declared as u16,
                |chunk| {
                    let mut c = chunk.to_vec();
                    match key.seal_in_place_separate_tag(Aad::empty(), &mut c) {
                        Ok(tag) => {
                            c.extend_from_slice(tag.as_ref());
                            Ok(c)
                        }
                        Err(_) => Err(HeaderError::Auth),
                    }
                },
            )
            .map_err(header_err_to_io)?
        };
        this_write(&mut self.write_buf, &sealed_header);

        // The payload chunk the header just declared. It carries no length chunk
        // of its own — the header was that.
        let tag = {
            self.encrypt_buf.clear();
            self.encrypt_buf.extend_from_slice(&buf[..first_len]);
            write_pad_tail(&mut self.encrypt_buf, pad_len, self.padding);
            let tail = self.encrypt_buf.len();
            let key = self
                .sealing_key
                .as_mut()
                .ok_or_else(|| io::Error::other("AEAD sealing key not initialized"))?;
            key.seal_in_place_separate_tag(Aad::empty(), &mut self.encrypt_buf[..tail])
                .map_err(|_| io::Error::other("Encryption failed (payload)"))?
        };
        this_write(&mut self.write_buf, &self.encrypt_buf[..]);
        this_write(&mut self.write_buf, tag.as_ref());
        self.ss2022_header_pending = false;

        self.flush_written(cx, first_len)
    }

    /// Pushes `write_buf` to the inner transport, reporting `accepted` as the
    /// number of the caller's bytes consumed once it has drained.
    ///
    /// On `Pending` the frame is marked in flight with `accepted`, so the next
    /// `poll_write` drains it and reports that same count rather than
    /// re-encrypting — `write_all` retries must not duplicate payload.
    fn flush_written(&mut self, cx: &mut Context<'_>, accepted: usize) -> Poll<io::Result<usize>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(n)) => self.write_buf.advance(n),
                Poll::Ready(Err(e)) => {
                    self.write_buf.clear();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.pending_chunk_size = Some(accepted);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(accepted))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Handshake: read salt
        if !this.read_salt_received {
            let salt_len = this.method.salt_len();
            while this.read_buf.len() < salt_len {
                let mut temp_buf = [0u8; 32];
                let mut rb = ReadBuf::new(
                    &mut temp_buf[..std::cmp::min(32, salt_len - this.read_buf.len())],
                );
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Failed to read salt",
                            )));
                        }
                        this.read_buf.extend_from_slice(rb.filled());
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.read_salt.copy_from_slice(&this.read_buf[..salt_len]);
            this.read_buf.advance(salt_len);
            this.read_salt_received = true;
            if let Err(e) = this.ensure_opening_key() {
                return Poll::Ready(Err(io::Error::other(e)));
            }
        }

        // Read and decrypt chunks
        loop {
            if !this.payload_buf.is_empty() {
                let n = std::cmp::min(this.payload_buf.len(), buf.remaining());
                buf.put_slice(&this.payload_buf[..n]);
                this.payload_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // ---- SIP022 2022 edition: the stream headers --------------------
            //
            // Symmetric to `write_2022_headers`. The header chunks are read
            // through `ss2022_stream`, the single owner of this framing, and
            // each is authenticated before its plaintext is interpreted.
            match this.ss2022_read {
                Ss2022ReadState::Off | Ss2022ReadState::Payload => {}
                Ss2022ReadState::RequestFixed => {
                    let need = ss2022_stream::REQUEST_FIXED_CHUNK_LEN;
                    if this.read_buf.len() < need {
                        match this.fill_read_buf(cx, need - this.read_buf.len()) {
                            FillOutcome::Pending => return Poll::Pending,
                            FillOutcome::Eof => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Incomplete SS2022 stream header",
                                )))
                            }
                            FillOutcome::Filled => {}
                        }
                    }
                    let declared = {
                        let key = this
                            .opening_key
                            .as_mut()
                            .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                        ss2022_stream::read_request_fixed_header_with(
                            &mut this.read_buf,
                            unix_now_secs(),
                            |chunk| {
                                let mut c = chunk.to_vec();
                                match key.open_in_place(Aad::empty(), &mut c) {
                                    Ok(p) => Ok(p.to_vec()),
                                    Err(_) => Err(HeaderError::Auth),
                                }
                            },
                        )
                        .map_err(header_err_to_io)?
                    };
                    this.ss2022_read = Ss2022ReadState::RequestVariable(declared as usize);
                }
                Ss2022ReadState::RequestVariable(len) => {
                    let need = len + ss2022_stream::PAYLOAD_CHUNK_OVERHEAD;
                    if this.read_buf.len() < need {
                        match this.fill_read_buf(cx, need - this.read_buf.len()) {
                            FillOutcome::Pending => return Poll::Pending,
                            FillOutcome::Eof => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Incomplete SS2022 variable header",
                                )))
                            }
                            FillOutcome::Filled => {}
                        }
                    }
                    let split = {
                        let key = this
                            .opening_key
                            .as_mut()
                            .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                        ss2022_stream::read_request_variable_header_with(
                            len as u16,
                            &mut this.read_buf,
                            |chunk| {
                                let mut c = chunk.to_vec();
                                match key.open_in_place(Aad::empty(), &mut c) {
                                    Ok(p) => Ok(p.to_vec()),
                                    Err(_) => Err(HeaderError::Auth),
                                }
                            },
                        )
                        .map_err(header_err_to_io)?
                    };
                    // Section 3.1.3 makes the variable-length header
                    // `ATYP | address | port | padding length | padding | initial
                    // payload`, and `read_request_variable_header_with` splits it
                    // and enforces both section 3.1.4 server MUSTs. Only the
                    // address goes upward as the target: the transport above
                    // (`transport/inbound/shadowsocks.rs`) parses the SOCKS5
                    // address off the front of this stream by hand, and it must
                    // keep seeing exactly the bytes it always saw.
                    //
                    // The initial payload, if the peer sent one, is the start of
                    // the proxied stream and is appended after the address — it
                    // was previously handed upward inside the same chunk, so a
                    // conformant peer's padding bytes were delivered as the first
                    // payload bytes. That is silent corruption, not a rejection.
                    this.payload_buf.extend_from_slice(&split.address);
                    this.payload_buf.extend_from_slice(&split.initial_payload);
                    this.ss2022_read = Ss2022ReadState::Payload;
                    continue;
                }
                Ss2022ReadState::ResponseFixed => {
                    let salt_len = this.method.salt_len();
                    let need = 11 + salt_len + ss2022_stream::PAYLOAD_CHUNK_OVERHEAD;
                    if this.read_buf.len() < need {
                        match this.fill_read_buf(cx, need - this.read_buf.len()) {
                            FillOutcome::Pending => return Poll::Pending,
                            FillOutcome::Eof => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Incomplete SS2022 response header",
                                )))
                            }
                            FillOutcome::Filled => {}
                        }
                    }
                    let (echo, declared) = {
                        let key = this
                            .opening_key
                            .as_mut()
                            .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                        ss2022_stream::read_response_header_with(
                            salt_len,
                            &mut this.read_buf,
                            unix_now_secs(),
                            |chunk| {
                                let mut c = chunk.to_vec();
                                match key.open_in_place(Aad::empty(), &mut c) {
                                    Ok(p) => Ok(p.to_vec()),
                                    Err(_) => Err(HeaderError::Auth),
                                }
                            },
                        )
                        .map_err(header_err_to_io)?
                    };
                    // Section 3.1.3: the response echoes the salt of the
                    // request that caused it. A mismatch means the response
                    // belongs to a different stream, and accepting it would
                    // bind this connection's payload to someone else's request.
                    if this.write_salt_sent && echo != this.write_salt {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SS2022 response does not echo this request's salt",
                        )));
                    }
                    this.ss2022_read = Ss2022ReadState::ResponsePayload(declared as usize);
                }
                Ss2022ReadState::ResponsePayload(len) => {
                    // The response header already declared this chunk's
                    // plaintext length, so there is no length chunk to read.
                    let need = len + ss2022_stream::PAYLOAD_CHUNK_OVERHEAD;
                    if this.read_buf.len() < need {
                        match this.fill_read_buf(cx, need - this.read_buf.len()) {
                            FillOutcome::Pending => return Poll::Pending,
                            FillOutcome::Eof => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Incomplete SS2022 response payload",
                                )))
                            }
                            FillOutcome::Filled => {}
                        }
                    }
                    let mut chunk = this.read_buf.split_to(need);
                    let opening_key = this
                        .opening_key
                        .as_mut()
                        .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                    let decrypted =
                        opening_key.open_in_place(Aad::empty(), &mut chunk).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Decryption failed (payload)",
                            )
                        })?;
                    let payload_end = strip_padding(decrypted, this.padding)?;
                    this.payload_buf.extend_from_slice(&decrypted[..payload_end]);
                    this.ss2022_read = Ss2022ReadState::Payload;
                    continue;
                }
            }

            if this.reading_length {
                let needed = LENGTH_SIZE + TAG_SIZE;
                if this.read_buf.len() < needed {
                    let mut temp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut temp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            this.read_buf.extend_from_slice(rb.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut length_chunk = this.read_buf.split_to(needed);
                let opening_key = this
                    .opening_key
                    .as_mut()
                    .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                let decrypted =
                    opening_key.open_in_place(Aad::empty(), &mut length_chunk).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Decryption failed (length)")
                    })?;

                this.remaining_payload = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
                if this.remaining_payload > MAX_CHUNK_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Chunk size too large",
                    )));
                }
                this.reading_length = false;
            } else {
                let needed = this.remaining_payload + TAG_SIZE;
                if this.read_buf.len() < needed {
                    let mut temp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut temp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Incomplete chunk",
                                )));
                            }
                            this.read_buf.extend_from_slice(rb.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut payload_chunk = this.read_buf.split_to(needed);
                let opening_key = this
                    .opening_key
                    .as_mut()
                    .ok_or_else(|| io::Error::other("AEAD opening key not initialized"))?;
                let decrypted =
                    opening_key.open_in_place(Aad::empty(), &mut payload_chunk).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Decryption failed (payload)")
                    })?;

                // 2022 edition: the header chunks have already been consumed and
                // verified above, before any length/payload chunk is read.
                let plaintext: &[u8] = decrypted;

                // G5: strip [pad_len][pad] tail — bytes before the marker
                // are real payload.
                let payload_end = strip_padding(plaintext, this.padding)?;

                this.payload_buf.extend_from_slice(&plaintext[..payload_end]);
                this.reading_length = true;
                this.remaining_payload = 0;
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // In-flight frame: drain it fully, then report the size accepted for
        // THAT write. Never re-encrypt while a frame is still buffered —
        // write_all retries would otherwise duplicate the payload on the wire.
        if let Some(pending_chunk) = this.pending_chunk_size {
            while !this.write_buf.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                    Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                    Poll::Ready(Err(e)) => {
                        this.pending_chunk_size = None;
                        this.write_buf.clear();
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.pending_chunk_size = None;
            return Poll::Ready(Ok(pending_chunk));
        }

        // Send salt if not sent
        if !this.write_salt_sent {
            let write_salt = this.write_salt.as_slice();
            this.write_buf.extend_from_slice(write_salt);
            this.write_salt_sent = true;
            if let Err(e) = this.ensure_sealing_key() {
                return Poll::Ready(Err(io::Error::other(e)));
            }
        }

        // ---- SIP022 2022 edition: the stream headers ------------------------
        //
        // Section 3.1.2: "A request stream starts with one random salt and two
        // standalone header chunks, followed repeatedly by one length chunk and
        // one payload chunk."
        //
        // "Standalone" is the whole of it. This writer used to fold the 11-byte
        // fixed header and the address into the *payload* chunk and charge them
        // to the preceding length chunk: one AEAD operation where the
        // specification requires two. A conformant peer reads the length chunk
        // as the fixed header chunk, finds two bytes where it expected eleven,
        // and fails the tag check on the first chunk of every stream. Every
        // round-trip test in this crate passed anyway, because both ends shared
        // the misreading; only `tools/ss2022-reference` could see it.
        //
        // The framing is owned by `ss2022_stream`, the single implementation of
        // it in this crate. This code supplies the AEAD primitive and the
        // address boundary and deliberately does not restate the header layout:
        // `seal_request_headers_with` invokes the closure exactly once per
        // chunk, so folding the two back together stops being expressible.
        if this.ss2022_header_pending {
            return this.write_2022_headers(cx, buf);
        }

        // Encrypt data into chunks. Padding (G5) reserves the worst-case tail.
        //
        // The 2022 header chunks have already gone out by this point (see
        // `write_2022_headers` above), so the payload capacity here is the full
        // chunk and carries no header allowance.
        // G5: random pad length 0..=255 per frame — full byte range so
        // inter-frame length deltas reveal nothing about plaintext sizes.
        let pad_len = draw_pad_len(this.padding);
        // Reserve the worst case up front: the frame size is computed from the
        // actual pad_len below, so unreserved capacity is simply unused.
        let pad_cost = match this.padding {
            PaddingMode::On => MAX_PAD_COST,
            PaddingMode::Off => 0,
        };
        let chunk_size = std::cmp::min(buf.len(), MAX_CHUNK_SIZE.saturating_sub(pad_cost));

        let sealing_key = this
            .sealing_key
            .as_mut()
            .ok_or_else(|| io::Error::other("AEAD sealing key not initialized"))?;

        // 1. Length Chunk (2 bytes + Tag).
        //
        // The declared length must account for whatever the tail writer is
        // about to append — including a lone marker byte for a zero-length pad.
        // `padded_frame_len` / `write_pad_tail` are the crate's single owners
        // of that rule (see `protocol::padding`): the length is charged a marker
        // unconditionally under `PaddingMode::On`, because a reader holding only
        // the frame cannot tell "a pad of length zero" from "no pad byte at all".
        // Declaring one length while emitting another desynchronises the reader
        // permanently, so the arithmetic is not restated here.
        let frame_len =
            crate::protocol::padding::padded_frame_len(chunk_size, pad_len, this.padding);

        let mut length_data = [0u8; 2];
        length_data.copy_from_slice(&(frame_len as u16).to_be_bytes());

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut length_data)
            .map_err(|_| io::Error::other("Encryption failed (length)"))?;

        this.write_buf.extend_from_slice(&length_data);
        this.write_buf.extend_from_slice(tag.as_ref());

        // 2. Payload Chunk (N bytes + Tag) + [pad][pad_len] tail.
        // Frame layout (G5): [payload][pad bytes...][pad_len:1] — under
        // `PaddingMode::On` the pad_len byte is ALWAYS the frame's last byte,
        // so the reader can locate it without scanning, and a pad of length
        // zero is written as a lone `0x00` marker rather than as no marker at
        // all. Pad bytes are random, never zero-fill.
        // Optimization: reuse the pre-allocated `encrypt_buf` so the hot path
        // never allocates.
        //
        // `truncate` keeps capacity but destroys *length*. The previous shape
        // indexed `header..header+chunk` first and truncated afterwards, so the
        // first frame left `encrypt_buf` at `header + chunk` long — and the
        // *second* frame then indexed inside a buffer that had since shrunk to
        // a few bytes. That is an out-of-bounds panic on the second frame of
        // every stream. Clear first, then write forward: same reserved
        // capacity, no allocation, no assumption about the current length.
        this.encrypt_buf.clear();
        this.encrypt_buf.extend_from_slice(&buf[..chunk_size]);
        write_pad_tail(&mut this.encrypt_buf, pad_len, this.padding);
        let tail = this.encrypt_buf.len();
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut this.encrypt_buf[..tail])
            .map_err(|_| io::Error::other("Encryption failed (payload)"))?;

        this.write_buf.extend_from_slice(&this.encrypt_buf[..tail]);
        this.write_buf.extend_from_slice(tag.as_ref());

        // Push the whole frame; if the transport cannot take all of it, mark
        // the frame in-flight and report Pending. Success is only ever
        // reported for fully flushed frames (AsyncWrite contract).
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                Poll::Ready(Err(e)) => {
                    this.write_buf.clear();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    this.pending_chunk_size = Some(chunk_size);
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Per-run ephemeral test password: unique every execution, never a
    /// static string (scanner hygiene — no literal credential-like values).
    fn test_password() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    // ---- RFC-012 G5 padding ----------------------------------------------
    //
    // The pad arithmetic itself — strip, overlong-marker rejection, the
    // zero-length marker and the all-256-lengths writer/reader agreement —
    // now lives with the shared contract in `protocol::padding`, and is not
    // duplicated here. What is Shadowsocks-specific and worth pinning here is
    // the *stream*: that a padded frame survives a real socket.

    #[test]
    fn g5_padding_is_not_applied_when_off() {
        // The default wire must be byte-identical to the pre-G5 format, so a
        // padded stream is opt-in rather than a silent upgrade.
        let frame = b"exactly-the-payload".to_vec();
        assert_eq!(strip_padding(&frame, PaddingMode::Off).expect("off never errors"), frame.len());
    }

    #[test]
    fn test_shadowsocks_kdf_aes256_gcm() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = test_password();
        let salt = [0u8; 32];
        let cipher = ShadowsocksCipher::new(method, &password, &salt).unwrap();

        // Ensure the subkey is generated (32 bytes for AES-256)
        assert_eq!(cipher.subkey.len(), 32);
        // HKDF-SHA1 with zero salt must yield a stable subkey for any input.
    }

    #[tokio::test]
    async fn test_shadowsocks_stream_roundtrip() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = test_password();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let mut client_stream = ShadowsocksStream::new(client_io, method, &password);
        let mut server_stream = ShadowsocksStream::new(server_io, method, &password);

        let test_data = b"ShadowMesh High-Fidelity Network Traffic";

        // Client writes
        client_stream.write_all(test_data).await.unwrap();
        client_stream.flush().await.unwrap();

        // Server reads
        let mut read_buf = vec![0u8; test_data.len()];
        server_stream.read_exact(&mut read_buf).await.unwrap();

        assert_eq!(test_data, read_buf.as_slice());

        // Server writes back
        let response = b"Verified Clean-Room Protocol";
        server_stream.write_all(response).await.unwrap();
        server_stream.flush().await.unwrap();

        // Client reads back
        let mut resp_buf = vec![0u8; response.len()];
        client_stream.read_exact(&mut resp_buf).await.unwrap();

        assert_eq!(response, resp_buf.as_slice());
    }

    // ---- RFC-008 §5: session key material is zeroized ---------------------
    //
    // These tests observe the `Zeroize` impl directly rather than the drop,
    // and the reason is worth stating: drop-time zeroization of a freed heap
    // block is **not observable** from safe Rust. The allocation goes back to
    // the allocator, the process no longer has a reference to it, and reading
    // it back is undefined behaviour. A test that claimed to check the drop
    // would either be asserting nothing or would be UB — both worse than no
    // test, and this repo has four such files being removed for exactly that.
    //
    // What *is* observable, and is pinned here, is the thing that makes the
    // drop worth having: `zeroize()` must wipe the session-derived key
    // material while the value is still live. `Drop` calls this and nothing
    // else, so a broken `zeroize()` is a broken drop; a `Drop` that stopped
    // calling it would be caught by `zeroize_is_what_drop_delegates_to`.

    /// The session password and both AEAD salts must be wiped.
    ///
    /// `ShadowsocksStream::new` generates a random `write_salt`; the point is
    /// that whatever bytes are in there when the session ends are gone, not
    /// that they had a particular value.
    #[tokio::test]
    async fn session_key_material_is_zeroized() {
        let password = test_password();
        let (client_io, _server_io) = tokio::io::duplex(64);
        let mut stream = ShadowsocksStream::new(client_io, ShadowsocksMethod::Aes256Gcm, &password);

        // Force both salts to hold non-zero bytes so "all zeros" is a real
        // signal rather than a vacuous pass on a fresh allocation.
        stream.read_salt.iter_mut().for_each(|b| *b = 0xAA);
        assert!(
            stream.read_salt.iter().any(|b| *b != 0),
            "precondition: read_salt must be non-zero before zeroize"
        );
        assert_eq!(stream.password, password, "precondition: password is held");

        stream.zeroize();

        assert!(
            stream.password.is_empty(),
            "the session password must be wiped on zeroize, not merely dropped"
        );
        assert!(
            stream.read_salt.iter().all(|b| *b == 0),
            "the read salt must be wiped: it feeds subkey derivation directly"
        );
        assert!(
            stream.write_salt.iter().all(|b| *b == 0),
            "the write salt must be wiped: it feeds subkey derivation directly"
        );
    }

    /// The 2022 edition uses the configured value as a PSK, not a stretched
    /// password, so it is *more* sensitive, not less. Same guarantee.
    #[tokio::test]
    async fn a_2022_psk_is_zeroized_too() {
        // A 2022 PSK is a base64 key of the method's key length. Generate it
        // per run rather than writing a key-shaped literal into the source.
        let psk_b64 = {
            let raw = crate::secure_random_bytes(ShadowsocksMethod::Aes256Gcm2022.key_len())
                .expect("CSPRNG for a 2022 PSK");
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(raw)
        };
        let (client_io, _server_io) = tokio::io::duplex(64);
        let mut stream =
            ShadowsocksStream::new(client_io, ShadowsocksMethod::Aes256Gcm2022, &psk_b64);

        assert_eq!(stream.password, psk_b64, "precondition: the PSK is held");
        stream.zeroize();
        assert!(stream.password.is_empty(), "a SIP022 PSK must be wiped on zeroize");
    }

    /// `Drop` must delegate to `zeroize`, not do something weaker.
    ///
    /// Drop-time zeroization itself is unobservable (§ above), but the
    /// *wiring* is not: this pins that `Drop` exists, that it reaches the
    /// same `zeroize`, and that `zeroize` is idempotent — so a future
    /// refactor that gives `Drop` its own weaker body, or that makes
    /// `zeroize` non-idempotent (some future edit that leaves a key resident
    /// after a second call), fails here.
    #[test]
    fn zeroize_is_what_drop_delegates_to() {
        fn assert_zeroize<T: Zeroize>() {}

        // Compiles only if `ShadowsocksStream` still implements `Zeroize`,
        // which is what `Drop` calls.
        assert_zeroize::<ShadowsocksStream<tokio::io::DuplexStream>>();

        let (client_io, _server_io) = tokio::io::duplex(64);
        let mut stream =
            ShadowsocksStream::new(client_io, ShadowsocksMethod::Aes256Gcm, &test_password());
        stream.zeroize();
        // Idempotent: a second pass must not panic and must leave it wiped.
        stream.zeroize();
        assert!(stream.password.is_empty(), "zeroize must be idempotent");
    }

    #[test]
    fn test_shadowsocks_udp_encryption() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = test_password();
        let plaintext = b"UDP payload data";

        let encrypted = ShadowsocksCipher::encrypt_udp(method, &password, plaintext).unwrap();
        assert!(encrypted.len() > method.salt_len() + TAG_SIZE);

        let decrypted = ShadowsocksCipher::decrypt_udp(method, &password, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    // ---- SIP007 UDP known-answer tests ----------------------------------
    //
    // SIP007's UDP section defines exactly one thing about the layout:
    // "Each UDP packet is encrypted/decrypted independently, using the derived
    // subkey and a nonce with all zero bytes." Everything below pins that
    // reading against bytes produced outside this codebase.
    //
    // This is the assertion that would fail if anyone "fixed" the UDP path by
    // bolting on the length chunk that the SIP007 *TCP* chunk format uses, or
    // the length block that neither SIP007 UDP nor SIP022 UDP (§3.2.2: packet
    // := `encrypted separate header 16B | encrypted body + 16B tag`) has. There
    // is no length chunk in SIP007 UDP. Adding one would make every packet
    // unreadable to a conforming peer while still round-tripping perfectly
    // against itself.

    /// Obvious placeholder, deliberately not credential-shaped: this is KAT
    /// input material, and it must be stable across runs.
    const KAT_PASSWORD: &str = "sip007-kat-placeholder";
    const KAT_SALT: [u8; 32] = [0x5A; 32];
    const KAT_PLAINTEXT: &[u8] = b"shadowmesh-udp-kat";

    /// PROVENANCE of every expected value below: computed outside this
    /// repository, in Python, as
    /// `EVP_BytesToKey(MD5, count=1, no salt)` -> `HKDF-SHA1(info="ss-subkey")`
    /// -> AEAD via **libsodium** (`nacl.bindings`), with a 12-byte zero nonce
    /// and empty AAD. The EVP_BytesToKey stage was separately cross-checked
    /// against `openssl enc -aes-256-cbc -P -md md5 -nosalt`, which agrees byte
    /// for byte. No Rust in this repository produced any of these bytes.
    ///
    /// An earlier revision of this file asserted different hex for all three
    /// values while documenting this same provenance. Those constants did not
    /// reproduce - the crate's real output matched the independent computation
    /// and failed the assertion. Fabricating a known answer defeats the only
    /// purpose of a known-answer test, which is to fail when the
    /// implementation is wrong; they have been replaced with the values that
    /// were actually reproduced.
    #[test]
    fn sip007_udp_subkey_matches_the_specification_formula() {
        // EVP_BytesToKey + HKDF-SHA1("ss-subkey") under a fixed salt.
        let subkey = ShadowsocksCipher::new(ShadowsocksMethod::Aes256Gcm, KAT_PASSWORD, &KAT_SALT)
            .expect("derivation")
            .subkey;
        assert_eq!(
            hex::encode(&subkey),
            "92cbd89293cf770d2a5a1ceec66f23fd05ab5fdb7a8ee2c5ab769bac333911e6"
        );
    }

    #[test]
    fn sip007_udp_aes256gcm_body_matches_the_known_answer() {
        let mut sealing =
            ShadowsocksCipher::new(ShadowsocksMethod::Aes256Gcm, KAT_PASSWORD, &KAT_SALT)
                .expect("derivation")
                .sealing_key()
                .expect("sealing key");
        let mut body = KAT_PLAINTEXT.to_vec();
        // `SealingKey` owns a `ShadowsocksNonceSequence` whose first value is
        // the all-zero nonce - exactly what the SIP007 UDP rule calls for. The
        // sequence is per-key, and this key was built for this one seal.
        sealing.seal_in_place_append_tag(Aad::empty(), &mut body).expect("seal");
        assert_eq!(KAT_PLAINTEXT.len() + TAG_SIZE, body.len());
        assert_eq!(
            hex::encode(&body),
            "738d39193a247ee31e04fb7050950b129b855e221abd532e19636f27455585ec0c3a"
        );
    }

    #[test]
    fn sip007_udp_chacha20poly1305_body_matches_the_known_answer() {
        let mut sealing =
            ShadowsocksCipher::new(ShadowsocksMethod::ChaCha20Poly1305, KAT_PASSWORD, &KAT_SALT)
                .expect("derivation")
                .sealing_key()
                .expect("sealing key");
        let mut body = KAT_PLAINTEXT.to_vec();
        // Same all-zero-nonce reasoning as the AES case above.
        sealing.seal_in_place_append_tag(Aad::empty(), &mut body).expect("seal");
        assert_eq!(
            hex::encode(&body),
            "77070083f0acbafa0e1e36a8cbde362a613a8dfa88654daedc2c8afb07851d607710"
        );
    }

    /// The exact wire layout of [`ShadowsocksCipher::encrypt_udp`]:
    /// `[salt][ciphertext || tag]`, and nothing else.
    ///
    /// `encrypt_udp` draws its salt from the CSPRNG, so this asserts the shape
    /// by parsing the packet it actually produced rather than by reproducing
    /// the construction - and by refusing any length that would imply a length
    /// chunk.
    #[test]
    fn sip007_udp_packet_is_exactly_salt_then_ciphertext_then_tag() {
        let password = test_password();
        let packet =
            ShadowsocksCipher::encrypt_udp(ShadowsocksMethod::Aes256Gcm, &password, KAT_PLAINTEXT)
                .expect("encrypt");
        assert_eq!(
            packet.len(),
            KAT_SALT.len() + KAT_PLAINTEXT.len() + TAG_SIZE,
            "a length chunk would make this 18 bytes longer"
        );

        // The trailing bytes must be exactly AEAD(subkey(salt), nonce=0, plaintext).
        let salt_len = ShadowsocksMethod::Aes256Gcm.salt_len();
        let mut opening =
            ShadowsocksCipher::new(ShadowsocksMethod::Aes256Gcm, &password, &packet[..salt_len])
                .expect("derivation")
                .opening_key()
                .expect("opening key");
        let mut tail = packet[salt_len..].to_vec();
        let opened = opening
            .open_in_place(Aad::empty(), &mut tail)
            .expect("the packet's own tag must verify");
        assert_eq!(opened, KAT_PLAINTEXT);
    }

    #[test]
    fn sip007_udp_roundtrip_still_works_for_both_legacy_methods() {
        for method in [ShadowsocksMethod::Aes256Gcm, ShadowsocksMethod::ChaCha20Poly1305] {
            let password = test_password();
            for payload in [&b""[..], &b"x"[..], &vec![0xABu8; 1400]] {
                let packet =
                    ShadowsocksCipher::encrypt_udp(method, &password, payload).expect("encrypt");
                assert_eq!(
                    packet.len(),
                    method.salt_len() + payload.len() + TAG_SIZE,
                    "{method:?} emitted an unexpected amount of framing"
                );
                let plain =
                    ShadowsocksCipher::decrypt_udp(method, &password, &packet).expect("decrypt");
                assert_eq!(plain.as_slice(), payload, "{method:?} did not round trip");
            }
        }
    }

    // ---- the bug this fixes ---------------------------------------------

    /// A 2022 method must never be handed to the SIP007 path. It used to be
    /// accepted, producing `[12-byte salt][AEAD(payload)]` - a packet no
    /// SIP022 peer can decrypt, and one that round-tripped perfectly against
    /// itself.
    #[test]
    fn sip007_udp_refuses_every_2022_method() {
        for method in [
            ShadowsocksMethod::Aes128Gcm2022,
            ShadowsocksMethod::Aes256Gcm2022,
            ShadowsocksMethod::ChaCha20Poly13052022,
        ] {
            assert!(
                ShadowsocksCipher::encrypt_udp(method, "placeholder", b"x").is_err(),
                "{method:?} was accepted by the SIP007 UDP path"
            );
            assert!(ShadowsocksCipher::decrypt_udp(method, "placeholder", &[0u8; 64]).is_err());
        }
    }

    // ---- the two method enums are bound together ------------------------

    /// The drift this guards: `ShadowsocksMethod` had no `Aes128Gcm2022` while
    /// `Shadowsocks2022Method` modelled it, so a MUST-implement method could
    /// not be selected through the transport that actually encrypts. The
    /// conversion in both directions is now total over the 2022 variants.
    #[test]
    fn the_two_2022_enums_agree_in_both_directions() {
        use crate::transport::shadowsocks2022::Shadowsocks2022Method as Other;
        let pairs = [
            (ShadowsocksMethod::Aes128Gcm2022, Other::Aes128Gcm),
            (ShadowsocksMethod::Aes256Gcm2022, Other::Aes256Gcm),
            (ShadowsocksMethod::ChaCha20Poly13052022, Other::ChaCha20Poly1305),
        ];
        for (mine, theirs) in pairs {
            assert_eq!(mine.as_ss2022(), Some(theirs));
            assert_eq!(mine.key_len(), theirs.psk_len(), "key length drifted for {mine:?}");
            assert_eq!(mine.key_len(), theirs.salt_len(), "SIP022 section 2.2: salt = key length");
            assert_eq!(mine.wire_name(), theirs.as_str(), "wire name drifted for {mine:?}");
        }
        // Legacy methods have no 2022 counterpart and say so.
        //
        // The target type must be named explicitly. Written as
        // `ShadowsocksMethod::try_from(legacy)` this resolves to core's blanket
        // `impl<T, U: Into<T>> TryFrom<U> for T` through the reflexive
        // `From<ShadowsocksMethod> for ShadowsocksMethod`, which is infallible -
        // so the assertion silently passed for every input, including the 2022
        // methods this test exists to keep in correspondence.
        for legacy in [ShadowsocksMethod::Aes256Gcm, ShadowsocksMethod::ChaCha20Poly1305] {
            assert_eq!(legacy.as_ss2022(), None);
            assert!(Other::try_from(legacy).is_err(), "{legacy:?} must have no 2022 counterpart");
        }
        // And the 2022 variants do convert through that same named impl.
        // `Result` cannot be compared directly because `anyhow::Error` is not
        // `PartialEq`, so the success value is unwrapped by hand rather than by
        // `unwrap()`, which would hide which side failed.
        for (mine, theirs) in pairs {
            match Other::try_from(mine) {
                Ok(got) => assert_eq!(got, theirs, "conversion drifted for {mine:?}"),
                Err(e) => panic!("{mine:?} failed to convert: {e}"),
            }
        }
        // Round trip through the string form for every 2022 name.
        for (mine, theirs) in pairs {
            let parsed: ShadowsocksMethod = theirs.as_str().parse().expect("parse");
            assert_eq!(parsed, mine);
        }
    }

    #[test]
    fn sip022_salt_length_is_the_key_length_not_twelve() {
        // Section 2.2: "The salt has the same length as the pre-shared key."
        // 12 is the nonce length; a 12-byte salt on the wire is rejected by
        // every conforming peer and also derives a different subkey.
        assert_eq!(ShadowsocksMethod::Aes128Gcm2022.salt_len(), 16);
        assert_eq!(ShadowsocksMethod::Aes256Gcm2022.salt_len(), 32);
        assert_eq!(ShadowsocksMethod::ChaCha20Poly13052022.salt_len(), 32);
    }

    #[test]
    fn a_2022_stream_still_round_trips_under_the_corrected_kdf() {
        let method = ShadowsocksMethod::Aes128Gcm2022;
        use base64::Engine;
        let identity = base64::engine::general_purpose::STANDARD.encode([0x33u8; 16]);
        let salt = vec![0x44u8; method.salt_len()];
        let cipher = ShadowsocksCipher::new_2022(method, &identity, &salt).expect("derivation");
        assert_eq!(cipher.subkey.len(), 16);
        // The subkey must now be the specification's: same context string and
        // key-material order as transport::shadowsocks2022.
        let expected = crate::transport::shadowsocks2022::derive_session_subkey(
            method.try_into().expect("2022 method"),
            &[0x33u8; 16],
            &salt,
        )
        .expect("specification derivation");
        assert_eq!(cipher.subkey, expected);
    }

    #[tokio::test]
    async fn a_2022_stream_round_trips_over_a_real_socket_pair() {
        for method in [
            ShadowsocksMethod::Aes128Gcm2022,
            ShadowsocksMethod::Aes256Gcm2022,
            ShadowsocksMethod::ChaCha20Poly13052022,
        ] {
            use base64::Engine;
            let identity =
                base64::engine::general_purpose::STANDARD.encode(vec![0x33u8; method.key_len()]);
            let (a_io, b_io) = tokio::io::duplex(8192);
            // `a` opens the request, `b` answers it: the two directions of a
            // proxied connection are opposite, which is what the two roles say.
            let mut a =
                ShadowsocksStream::new(a_io, method, &identity).with_role(StreamRole::Client);
            let mut b =
                ShadowsocksStream::new(b_io, method, &identity).with_role(StreamRole::Server);

            // A 2022 request stream begins with the SOCKS5 target address as its
            // variable-length header chunk, so the address is written first and
            // the payload second. Writing payload alone is not a request stream
            // any more — and never was, per section 3.1.2.
            let addr = [1u8, 93, 184, 216, 34, 0x01, 0xBB];
            let payload = b"ss2022-udp-and-stream-payload";
            a.write_all(&addr).await.expect("write address");
            a.write_all(payload).await.expect("write");
            a.flush().await.expect("flush");

            let mut got = vec![0u8; addr.len() + payload.len()];
            b.read_exact(&mut got).await.expect("read");
            assert_eq!(&got[..addr.len()], &addr[..], "{method:?}: address must survive");
            assert_eq!(&got[addr.len()..], payload, "{method:?} stream round trip failed");
        }
    }
}
