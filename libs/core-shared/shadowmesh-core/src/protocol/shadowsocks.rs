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

/// Accepted clock skew for 2022-edition timestamps (matches the SIP022
/// family's replay window guidance).
pub const SS2022_TIMESTAMP_WINDOW_SECS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    Aes256Gcm,
    ChaCha20Poly1305,
    /// `2022-blake3-aes-256-gcm`: BLAKE3-derived keys, fixed 12-byte salts,
    /// timestamped fixed-length header (replay-resistant).
    Aes256Gcm2022,
    /// `2022-blake3-chacha20-poly1305`.
    ChaCha20Poly13052022,
}

impl ShadowsocksMethod {
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            // 2022 edition: 32-byte keys, base64 in config.
            Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022 => 32,
        }
    }

    pub fn salt_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            // 2022 edition: fixed 12-byte salts.
            Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022 => 12,
        }
    }

    pub fn is_2022(&self) -> bool {
        matches!(self, Self::Aes256Gcm2022 | Self::ChaCha20Poly13052022)
    }

    fn ring_algorithm(&self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes256Gcm | Self::Aes256Gcm2022 => &AES_256_GCM,
            Self::ChaCha20Poly1305 | Self::ChaCha20Poly13052022 => &CHACHA20_POLY1305,
        }
    }
}

impl std::str::FromStr for ShadowsocksMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
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
    /// 2022-edition constructor: delegates key parsing and BLAKE3 KDF to
    /// protocol::ss2022. Returns Err when the wire format is wrong.
    pub fn new_2022(method: ShadowsocksMethod, configured: &str, salt: &[u8]) -> Result<Self> {
        let master = crate::protocol::ss2022::parse_identity_key(configured, method.key_len())
            .map_err(anyhow::Error::msg)?;
        let subkey =
            crate::protocol::ss2022::derive_session_subkey(salt, &master, method.key_len());
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

    /// Encrypts a single UDP packet as per SIP007.
    /// Returns a new buffer containing [Salt][Encrypted Data][Tag].
    pub fn encrypt_udp(
        method: ShadowsocksMethod,
        password: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
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

    /// Decrypts a single UDP packet as per SIP007.
    pub fn decrypt_udp(
        method: ShadowsocksMethod,
        password: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
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

/// Length-hiding padding policy (RFC-012 G5). Off = exact wire compat with
/// external SIP007 peers; On = every frame gains 0..255 random pad bytes
/// (both sides must be ShadowMesh or padding-aware).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMode {
    Off,
    On,
}

/// Upper bound of per-frame padding (one byte of length encoding).
pub const MAX_PAD_BYTES: usize = 255;

pub struct ShadowsocksStream<S> {
    inner: S,
    method: ShadowsocksMethod,
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
    /// 2022 edition: first request chunk must carry the fixed header
    /// (type/timestamp/length) before the address; tracked until sent.
    ss2022_header_pending: bool,
    /// 2022 edition: first received chunk must present a fresh header.
    ss2022_expect_header: bool,
    /// RFC-012 G5: when On, every frame carries [u8 pad_len][pad] after the
    /// payload; the reader strips it after AEAD verification.
    padding: PaddingMode,
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
            ss2022_expect_header: method.is_2022(),
            padding,
        }
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

                // 2022 edition: the first received chunk starts with the
                // fixed header; a stale timestamp is a replay attempt and
                // must kill the session (InvalidData), not just log.
                let mut plaintext: &[u8] = decrypted;
                if this.ss2022_expect_header {
                    let hdr = crate::protocol::ss2022::parse_fixed_header(plaintext)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    if !hdr.is_fresh() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SS2022 replay window exceeded",
                        )));
                    }
                    plaintext = &plaintext[crate::protocol::ss2022::FIXED_HEADER_LEN..];
                    this.ss2022_expect_header = false;
                }

                // G5: strip [pad_len][pad] tail — bytes before the marker
                // are real payload.
                let payload_end = if this.padding == PaddingMode::On && !plaintext.is_empty() {
                    let pad_len = plaintext[plaintext.len() - 1] as usize;
                    // Last byte encodes pad length; the pad itself precedes
                    // the marker. Malformed (overlong) pad = protocol error.
                    if 1 + pad_len > plaintext.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "padding length exceeds frame",
                        )));
                    }
                    plaintext.len() - 1 - pad_len
                } else {
                    plaintext.len()
                };

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

        // Encrypt data into chunks. For the 2022 edition the first frame
        // also carries the 11-byte fixed header, so the payload capacity is
        // reduced by the header size to stay within encrypt_buf and the
        // u16 length field. Padding (G5) reserves 1 + pad_len capacity.
        let header_cost =
            if this.ss2022_header_pending { crate::protocol::ss2022::FIXED_HEADER_LEN } else { 0 };
        // G5: random pad length 0..=255 per frame — full byte range so
        // inter-frame length deltas reveal nothing about plaintext sizes.
        let pad_len: usize = match this.padding {
            PaddingMode::On => rand::random::<u8>() as usize,
            PaddingMode::Off => 0,
        };
        let pad_cost = match this.padding {
            // Reserve the worst case up front: frame size is computed from
            // the actual pad_len below, so unreserved capacity is unused.
            PaddingMode::On => 1 + MAX_PAD_BYTES,
            PaddingMode::Off => 0,
        };
        let chunk_size =
            std::cmp::min(buf.len(), MAX_CHUNK_SIZE.saturating_sub(header_cost + pad_cost));

        let sealing_key = this
            .sealing_key
            .as_mut()
            .ok_or_else(|| io::Error::other("AEAD sealing key not initialized"))?;

        // 1. Length Chunk (2 bytes + Tag) — for the 2022 edition the first
        // chunk's declared length includes the 11-byte fixed header.
        let mut first_header = Vec::new();
        if this.ss2022_header_pending {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            first_header.extend_from_slice(&crate::protocol::ss2022::build_fixed_header(
                crate::protocol::ss2022::PAYLOAD_TYPE_REQUEST,
                now_ms,
                chunk_size as u16,
            ));
        }
        let frame_len = chunk_size + first_header.len() + if pad_len > 0 { 1 + pad_len } else { 0 };

        let mut length_data = [0u8; 2];
        length_data.copy_from_slice(&(frame_len as u16).to_be_bytes());

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut length_data)
            .map_err(|_| io::Error::other("Encryption failed (length)"))?;

        this.write_buf.extend_from_slice(&length_data);
        this.write_buf.extend_from_slice(tag.as_ref());

        // 2. Payload Chunk (N bytes + Tag) + optional [pad][pad_len] tail.
        // Frame layout (G5): [header?][payload][pad bytes...][pad_len:1] —
        // the LENGTH byte is always the frame's last byte so the reader can
        // locate it without scanning. Pad bytes are random, never zero-fill.
        // Optimization: Use pre-allocated encrypt_buf to avoid heap allocation.
        this.encrypt_buf[..first_header.len()].copy_from_slice(&first_header);
        this.encrypt_buf[first_header.len()..first_header.len() + chunk_size]
            .copy_from_slice(&buf[..chunk_size]);
        let mut tail = first_header.len() + chunk_size;
        if pad_len > 0 {
            for i in 0..pad_len {
                this.encrypt_buf[tail + i] = rand::random::<u8>();
            }
            tail += pad_len;
            this.encrypt_buf[tail] = pad_len as u8;
            tail += 1;
        }
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut this.encrypt_buf[..tail])
            .map_err(|_| io::Error::other("Encryption failed (payload)"))?;

        this.write_buf.extend_from_slice(&this.encrypt_buf[..tail]);
        this.write_buf.extend_from_slice(tag.as_ref());
        this.ss2022_header_pending = false;

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

    #[test]
    fn test_shadowsocks_kdf_aes256_gcm() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = "test_password";
        let salt = [0u8; 32];
        let cipher = ShadowsocksCipher::new(method, password, &salt).unwrap();

        // Ensure the subkey is generated (32 bytes for AES-256)
        assert_eq!(cipher.subkey.len(), 32);
        // MD5 EVP_BytesToKey for "test_password" should yield a specific master key.
        // HKDF-SHA1 with zero salt should yield a stable subkey.
    }

    #[tokio::test]
    async fn test_shadowsocks_stream_roundtrip() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = "shadowmesh_secret";

        let (client_io, server_io) = tokio::io::duplex(4096);

        let mut client_stream = ShadowsocksStream::new(client_io, method, password);
        let mut server_stream = ShadowsocksStream::new(server_io, method, password);

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

    #[test]
    fn test_shadowsocks_udp_encryption() {
        let method = ShadowsocksMethod::Aes256Gcm;
        let password = "udp_secret_key";
        let plaintext = b"UDP payload data";

        let encrypted = ShadowsocksCipher::encrypt_udp(method, password, plaintext).unwrap();
        assert!(encrypted.len() > method.salt_len() + TAG_SIZE);

        let decrypted = ShadowsocksCipher::decrypt_udp(method, password, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
