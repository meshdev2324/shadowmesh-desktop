//! Minimal TLS 1.3 client with REALITY session-id authentication.
//!
//! rustls cannot inject REALITY auth into the ClientHello (no ClientHello
//! mutation API), so this module implements the subset of RFC 8446 required
//! to speak to an Xray/sing-box REALITY endpoint, byte-compatible with
//! Xray-core's `transport/internet/reality` client:
//!
//! - `session_id` plaintext: `[ver_x, ver_y, ver_z, 0x00, time_be32, short_id...]`
//!   sealed with AES-256-GCM under
//!   `auth_key = HKDF-SHA256(ECDH(ephemeral, server_reality_pub), salt = random[..20], info = "REALITY")`,
//!   nonce `random[20..32]`, AAD = raw ClientHello with zeroed session_id,
//!   ciphertext placed at `raw[39..71]`.
//! - Server identity: a single Ed25519 temp certificate whose signature is
//!   `HMAC-SHA512(auth_key, ed25519_pub)`; anything else (e.g. the genuine
//!   masquerade certificate) means authentication failed.
//!
//! Only peer-reviewed primitives are used (`ring`, `x25519-dalek`); this
//! module implements protocol framing, not new cryptography.

use crate::ShadowMeshError;
use bytes::{BufMut, BytesMut};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use ring::digest::{self, Algorithm as DigestAlg};
use ring::hmac::{self, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

/// Xray-core version bytes reported in the session_id (the server only
/// validates these when MinClientVer/MaxClientVer are configured).
const REALITY_CLIENT_VER: [u8; 3] = [26, 3, 27];

/// Fixed offset of the session_id *data* inside the ClientHello handshake
/// message (Go/uTLS layout: `raw[39..71]`, length byte at `raw[38]`).
const SESSION_ID_OFFSET: usize = 39;

/// Maximum wire size of one TLS record payload.
pub(crate) const MAX_RECORD: usize = 16 * 1024 + 256;

/// Negotiated cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl Suite {
    pub(crate) fn from_code(code: u16) -> Result<Self, ShadowMeshError> {
        match code {
            0x1301 => Ok(Self::Aes128GcmSha256),
            0x1302 => Ok(Self::Aes256GcmSha384),
            0x1303 => Ok(Self::ChaCha20Poly1305Sha256),
            other => Err(ShadowMeshError::Other(format!(
                "REALITY: server selected unsupported cipher suite {other:#06x}"
            ))),
        }
    }

    pub(crate) fn hash(self) -> &'static DigestAlg {
        match self {
            Self::Aes256GcmSha384 => &digest::SHA384,
            _ => &digest::SHA256,
        }
    }

    pub(crate) fn hmac_alg(self) -> &'static hmac::Algorithm {
        match self {
            Self::Aes256GcmSha384 => &HMAC_SHA384,
            _ => &HMAC_SHA256,
        }
    }

    pub(crate) fn aead(self, key: &[u8]) -> Result<LessSafeKey, ShadowMeshError> {
        let unbound = UnboundKey::new(aead_algorithm(self), key)
            .map_err(|_| ShadowMeshError::Other("REALITY: invalid AEAD key length".into()))?;
        Ok(LessSafeKey::new(unbound))
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }
}

pub(crate) fn aead_algorithm(suite: Suite) -> &'static ring::aead::Algorithm {
    match suite {
        Suite::Aes128GcmSha256 => &AES_128_GCM,
        Suite::Aes256GcmSha384 => &AES_256_GCM,
        Suite::ChaCha20Poly1305Sha256 => &CHACHA20_POLY1305,
    }
}

/// One direction's AEAD keys plus the running record sequence number.
pub(crate) struct DirectionKeys {
    pub(crate) key: Vec<u8>,
    pub(crate) iv: [u8; 12],
    pub(crate) seq: u64,
}

impl DirectionKeys {
    /// Derives `{key, iv}` from a traffic secret (RFC 8446 §7.3).
    pub(crate) fn from_traffic_secret(
        suite: Suite,
        traffic_secret: &[u8],
    ) -> Result<Self, ShadowMeshError> {
        let key = hkdf_expand_label(suite, traffic_secret, b"", b"key", &[], suite.key_len());
        let iv_vec = hkdf_expand_label(suite, traffic_secret, b"", b"iv", &[], 12);
        let iv = iv_vec
            .try_into()
            .map_err(|_| ShadowMeshError::Other("REALITY: failed to derive IV".into()))?;
        Ok(Self { key, iv, seq: 0 })
    }

    pub(crate) fn nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        self.seq += 1;
        nonce
    }
}

/// HKDF-Expand-Label per RFC 8446 §7.1: `HKDF-Expand(secret, "tls13 " + label + suffix, len)`.
pub(crate) fn hkdf_expand_label(
    suite: Suite,
    secret: &[u8],
    suffix: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label_len = 6 + label.len() + suffix.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.put_u16(len as u16);
    info.put_u8(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.extend_from_slice(suffix);
    info.put_u8(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(suite.hmac_alg(), secret, &info, len)
}

/// Raw HKDF-Expand (RFC 5869) on top of ring HMAC.
pub(crate) fn hkdf_expand(
    alg: &'static hmac::Algorithm,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Vec<u8> {
    let key = hmac::Key::new(*alg, prk);
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut block = t.clone();
        block.extend_from_slice(info);
        block.push(counter);
        t = hmac::sign(&key, &block).as_ref().to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// HKDF-Extract (RFC 5869): PRK = HMAC(salt, IKM).
pub(crate) fn hkdf_extract(alg: &'static hmac::Algorithm, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(*alg, salt), ikm).as_ref().to_vec()
}

/// TLS 1.3 record content types.
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

/// Handshake message types.
const HM_NEW_SESSION_TICKET: u8 = 4;
pub(crate) const HM_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HM_CERTIFICATE: u8 = 11;
pub(crate) const HM_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HM_FINISHED: u8 = 20;
pub(crate) const HM_CLIENT_HELLO: u8 = 1;

pub(crate) fn put_u16_vec(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.put_u16(bytes.len() as u16);
    buf.extend_from_slice(bytes);
}

pub(crate) fn put_u24(buf: &mut Vec<u8>, n: usize) {
    buf.extend_from_slice(&(n as u32).to_be_bytes()[1..4]);
}

/// A post-handshake REALITY TLS 1.3 stream carrying VLESS application data.
pub struct RealityTlsStream {
    sock: TcpStream,
    suite: Suite,
    /// REALITY authentication key; zeroized on drop (ZPII).
    auth_key: [u8; 32],
    write: DirectionKeys,
    read: DirectionKeys,
    /// Buffered bytes from the TCP socket (partial records live here).
    inbuf: BytesMut,
    /// Decrypted application payloads awaiting consumption.
    pending: BytesMut,
    /// Sealed records awaiting socket transmission (AsyncWrite path).
    outbuf: Vec<u8>,
}

impl Zeroize for RealityTlsStream {
    fn zeroize(&mut self) {
        self.auth_key.zeroize();
        self.write.key.zeroize();
        self.read.key.zeroize();
    }
}

impl Drop for RealityTlsStream {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RealityTlsStream {
    /// Performs the full REALITY TLS 1.3 handshake over an established TCP
    /// connection (the socket must already be protect()ed on Android).
    pub async fn connect(
        mut sock: TcpStream,
        reality_pub_key_b64: &str,
        short_id_hex: &str,
        sni_target: &str,
    ) -> Result<Self, ShadowMeshError> {
        use base64::Engine;

        // v6.9.16: Robust Base64 decoding for REALITY public keys.
        // Xray often uses URL-safe base64 (with _ and -). Try both.
        let pub_key_raw = reality_pub_key_b64.trim();
        let server_reality_pub_vec = base64::engine::general_purpose::STANDARD
            .decode(pub_key_raw)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(pub_key_raw))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pub_key_raw))
            .map_err(|_| {
                ShadowMeshError::Other("REALITY: invalid server public key encoding".into())
            })?;

        let server_reality_pub: [u8; 32] =
            server_reality_pub_vec.as_slice().try_into().map_err(|_| {
                ShadowMeshError::Other("REALITY: server public key must be 32 bytes".into())
            })?;

        let short_id = hex::decode(short_id_hex.trim())
            .map_err(|_| ShadowMeshError::Other("REALITY: invalid short_id hex".into()))?;
        if short_id.is_empty() || short_id.len() > 8 {
            return Err(ShadowMeshError::Other("REALITY: short_id must be 1..8 bytes".into()));
        }

        // ---- Ephemeral key share (dual-use: REALITY auth + TLS key exchange) ----
        let eph_priv = StaticSecret::random_from_rng(OsRng);
        let eph_pub = XPublicKey::from(&eph_priv);

        // ---- ClientHello (session_id zeroed at build time, sealed below) ----
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);

        let mut hello = Vec::with_capacity(512);
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version (TLS 1.2)
        hello.extend_from_slice(&random);
        hello.put_u8(32); // session_id length
        let sid_start = hello.len();
        hello.extend_from_slice(&[0u8; 32]); // session_id placeholder

        // Cipher Suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384
        put_u16_vec(&mut hello, &[0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);
        hello.extend_from_slice(&[0x01, 0x00]); // compression: null

        let mut ext = Vec::with_capacity(256);

        // 1. server_name (0x0000)
        ext.put_u16(0x0000);
        let mut sni = Vec::new();
        sni.put_u16((sni_target.len() + 3) as u16); // server_name_list length
        sni.put_u8(0); // host_name type
        put_u16_vec(&mut sni, sni_target.as_bytes()); // host_name length + name
        put_u16_vec(&mut ext, &sni);

        // 2. extended_master_secret (0x0017)
        ext.put_u16(0x0017);
        put_u16_vec(&mut ext, &[]);

        // 3. supported_groups (0x000a): x25519
        ext.put_u16(0x000a);
        put_u16_vec(&mut ext, &[0x00, 0x02, 0x00, 0x1d]);

        // 4. signature_algorithms (0x000d)
        ext.put_u16(0x000d);
        put_u16_vec(&mut ext, &[0x00, 0x08, 0x08, 0x04, 0x04, 0x03, 0x08, 0x07, 0x08, 0x05]);

        // 5. supported_versions (0x002b): TLS 1.3
        ext.put_u16(0x002b);
        put_u16_vec(&mut ext, &[0x02, 0x03, 0x04]);

        // 6. key_share (0x0033): x25519
        ext.put_u16(0x0033);
        let mut ks = Vec::new();
        ks.put_u16(34); // client_shares list length
        ks.put_u16(0x001d); // x25519 group
        put_u16_vec(&mut ks, eph_pub.as_bytes());
        put_u16_vec(&mut ext, &ks);

        // 7. ALPN (0x0010): h2, http/1.1
        ext.put_u16(0x0010);
        let mut alpn = Vec::new();
        alpn.put_u16(12); // identification_sequence_list length
        alpn.put_u8(2);
        alpn.extend_from_slice(b"h2");
        alpn.put_u8(8);
        alpn.extend_from_slice(b"http/1.1");
        put_u16_vec(&mut ext, &alpn);

        put_u16_vec(&mut hello, &ext);

        let mut ch_msg = Vec::with_capacity(hello.len() + 4);
        ch_msg.put_u8(HM_CLIENT_HELLO);
        put_u24(&mut ch_msg, hello.len());
        let body_start = ch_msg.len();
        ch_msg.extend_from_slice(&hello);

        // ---- REALITY session_id sealing (Xray client algorithm) ----
        let reality_shared = eph_priv.diffie_hellman(&XPublicKey::from(server_reality_pub));
        let auth_key: [u8; 32] = {
            // Server: hkdf.New(sha256, secret=AuthKey(ECDH), salt=random[:20], info="REALITY")
            // → PRK = HMAC-SHA256(key=random[:20], msg=shared)
            let prk = hkdf_extract(&HMAC_SHA256, &random[..20], reality_shared.as_bytes());
            hkdf_expand(&HMAC_SHA256, &prk, b"REALITY", 32)
                .try_into()
                .map_err(|_| ShadowMeshError::Other("REALITY: failed to expand auth_key".into()))?
        };

        let mut plain = [0u8; 16];
        plain[0..3].copy_from_slice(&REALITY_CLIENT_VER);
        let now = chrono::Utc::now().timestamp().max(0);
        plain[4..8].copy_from_slice(&(now as u32).to_be_bytes());
        plain[8..8 + short_id.len()].copy_from_slice(&short_id);

        let seal_key = Suite::Aes256GcmSha384.aead(&auth_key)?;
        let mut sealed = plain.to_vec();
        let seal_nonce = Nonce::try_assume_unique_for_key(&random[20..32])
            .map_err(|_| ShadowMeshError::Other("REALITY: bad nonce".into()))?;

        // AAD = full ClientHello message with zeroed session_id
        let tag = seal_key
            .seal_in_place_separate_tag(seal_nonce, Aad::from(&ch_msg), &mut sealed)
            .map_err(|_| ShadowMeshError::Other("REALITY: sealing failed".into()))?;

        // session_id DATA: [hdr 4][ver 2][random 32][sid_len 1] = offset 39
        // (sid_start points at the data within the body, after the length byte).
        let sid_offset = body_start + sid_start;
        assert_eq!(sid_offset, SESSION_ID_OFFSET, "REALITY: session_id offset invariant");
        ch_msg[sid_offset..sid_offset + 16].copy_from_slice(&sealed);
        ch_msg[sid_offset + 16..sid_offset + 32].copy_from_slice(tag.as_ref());

        if std::env::var("SHADOWMESH_DEBUG_CH").is_ok() {
            trace!("[CH-DEBUG] len={} hex={}", ch_msg.len(), hex::encode(&ch_msg));
        }
        send_record(&mut sock, CT_HANDSHAKE, &ch_msg).await?;

        // ---- ServerHello ----
        // v6.10.0 (RFC-015): the handshake buffer must persist across the
        // ServerHello and the encrypted flight — the server may pipeline
        // both flights in one TCP segment, and over-read bytes were
        // previously DISCARDED here (deadlock against fast servers).
        let mut inbuf = BytesMut::with_capacity(MAX_RECORD);
        let sh_msg = read_plaintext_handshake_record(&mut sock, &mut inbuf).await?;
        let (suite, server_share) = parse_server_hello(&sh_msg)?;

        // ---- TLS 1.3 key schedule ----
        let mut transcript = digest::Context::new(suite.hash());
        transcript.update(&ch_msg);
        transcript.update(&sh_msg);

        let hash_len = suite.hash().output_len();
        let zeros = vec![0u8; hash_len];
        let early = hkdf_extract(suite.hmac_alg(), &zeros, &zeros);
        let derived = hkdf_expand_label(suite, &early, b"", b"derived", &[], hash_len);
        let tls_shared = eph_priv.diffie_hellman(&XPublicKey::from(
            <[u8; 32]>::try_from(server_share.as_slice())
                .map_err(|_| ShadowMeshError::Other("REALITY: bad server key share".into()))?,
        ));
        let hs_secret = hkdf_extract(suite.hmac_alg(), &derived, tls_shared.as_bytes());

        let th_sh = transcript.clone().finish();
        let s_hs_traffic =
            hkdf_expand_label(suite, &hs_secret, b"", b"s hs traffic", th_sh.as_ref(), hash_len);
        let c_hs_traffic =
            hkdf_expand_label(suite, &hs_secret, b"", b"c hs traffic", th_sh.as_ref(), hash_len);
        let mut s_hs_keys = DirectionKeys::from_traffic_secret(suite, &s_hs_traffic)?;
        let _c_hs_keys = DirectionKeys::from_traffic_secret(suite, &c_hs_traffic)?;

        // ---- Encrypted handshake flight: EE, Certificate, CertificateVerify, Finished ----
        let mut hs_buf = BytesMut::new();
        let mut cert_pub: Option<Vec<u8>> = None;
        let mut seen_finished = false;
        while !seen_finished {
            let (content_type, payload) =
                read_encrypted_record(&mut sock, &mut inbuf, &mut s_hs_keys, suite).await?;
            if content_type == CT_ALERT {
                let desc = payload.get(1).copied().unwrap_or(0);
                return Err(ShadowMeshError::Other(format!(
                    "REALITY: server sent alert {desc} during handshake"
                )));
            }
            if content_type != CT_HANDSHAKE {
                return Err(ShadowMeshError::Other(format!(
                    "REALITY: unexpected record type {content_type} during handshake"
                )));
            }
            hs_buf.extend_from_slice(&payload);
            while hs_buf.len() >= 4 {
                let msg_type = hs_buf[0];
                let msg_len = u32::from_be_bytes([0, hs_buf[1], hs_buf[2], hs_buf[3]]) as usize;
                if hs_buf.len() < 4 + msg_len {
                    break;
                }
                let msg: Vec<u8> = hs_buf.split_to(4 + msg_len).to_vec();
                match msg_type {
                    HM_ENCRYPTED_EXTENSIONS => transcript.update(&msg),
                    HM_CERTIFICATE => {
                        let (pub_key, _) = parse_and_verify_temp_cert(&msg, &auth_key)?;
                        cert_pub = Some(pub_key);
                        transcript.update(&msg);
                    }
                    HM_CERTIFICATE_VERIFY => {
                        let pub_key = cert_pub.as_ref().ok_or_else(|| {
                            ShadowMeshError::Other(
                                "REALITY: CertificateVerify before Certificate".into(),
                            )
                        })?;
                        verify_certificate_verify(&msg, pub_key, &transcript)?;
                        transcript.update(&msg);
                    }
                    HM_FINISHED => {
                        verify_server_finished(&msg, &s_hs_traffic, suite, &transcript)?;
                        transcript.update(&msg);
                        seen_finished = true;
                    }
                    unknown => {
                        return Err(ShadowMeshError::Other(format!(
                            "REALITY: unexpected handshake message type {unknown}"
                        )))
                    }
                }
            }
        }

        // ---- Application secrets (transcript through server Finished) ----
        let derived2 = hkdf_expand_label(suite, &hs_secret, b"", b"derived", &[], hash_len);
        let master = hkdf_extract(suite.hmac_alg(), &derived2, &zeros);
        let th_fin = transcript.clone().finish();
        let c_ap_traffic =
            hkdf_expand_label(suite, &master, b"", b"c ap traffic", th_fin.as_ref(), hash_len);
        let s_ap_traffic =
            hkdf_expand_label(suite, &master, b"", b"s ap traffic", th_fin.as_ref(), hash_len);
        let write_keys = DirectionKeys::from_traffic_secret(suite, &c_ap_traffic)?;
        let read_keys = DirectionKeys::from_traffic_secret(suite, &s_ap_traffic)?;

        // ---- Client Finished (encrypted record, outer type 23, inner type 22) ----
        let c_finished_key =
            hkdf_expand_label(suite, &c_hs_traffic, b"", b"finished", &[], hash_len);
        let th = transcript.clone().finish();
        let verify_data =
            hmac::sign(&hmac::Key::new(*suite.hmac_alg(), &c_finished_key), th.as_ref());
        let mut fin_msg = Vec::with_capacity(4 + verify_data.as_ref().len() + 1);
        fin_msg.put_u8(HM_FINISHED);
        put_u24(&mut fin_msg, verify_data.as_ref().len());
        fin_msg.extend_from_slice(verify_data.as_ref());
        fin_msg.push(CT_HANDSHAKE); // inner content type

        let mut write = write_keys;
        let fin_record = seal_record(&mut write, suite, CT_APPLICATION_DATA, &mut fin_msg)?;
        sock.write_all(&fin_record).await.map_err(|e| {
            ShadowMeshError::IoError(format!("REALITY: failed to send Finished: {e}"))
        })?;

        debug!("SHADOWMESH_RUST: REALITY TLS 1.3 handshake complete");
        Ok(Self {
            sock,
            suite,
            auth_key,
            write,
            read: read_keys,
            inbuf,
            pending: BytesMut::new(),
            outbuf: Vec::new(),
        })
    }

    /// Writes application data as encrypted TLS 1.3 records.
    pub async fn write_app(&mut self, data: &[u8]) -> Result<(), ShadowMeshError> {
        for chunk in data.chunks(14 * 1024) {
            let mut payload = chunk.to_vec();
            payload.push(CT_APPLICATION_DATA); // inner content type
            let record =
                seal_record(&mut self.write, self.suite, CT_APPLICATION_DATA, &mut payload)?;
            self.sock
                .write_all(&record)
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("REALITY: write failed: {e}")))?;
        }
        self.sock.flush().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Reads the next application-data payload.
    /// Returns `Ok(None)` on clean EOF. Cancel-safe: partial reads stay buffered.
    pub async fn read_app(&mut self) -> Result<Option<Vec<u8>>, ShadowMeshError> {
        loop {
            if !self.pending.is_empty() {
                return Ok(Some(self.pending.split().to_vec()));
            }
            if !self.fill_and_decrypt().await? {
                return Ok(None);
            }
        }
    }

    /// Reads bytes until at least one full record can be decrypted; returns
    /// `false` on clean EOF. Partial TCP reads remain buffered (cancel-safe).
    async fn fill_and_decrypt(&mut self) -> Result<bool, ShadowMeshError> {
        loop {
            // Decrypt whatever complete records are already buffered.
            decrypt_available_records(
                &mut self.inbuf,
                &mut self.pending,
                &mut self.read,
                self.suite,
            )?;
            if !self.pending.is_empty() {
                return Ok(true);
            }
            let mut chunk = [0u8; MAX_RECORD];
            let n = self
                .sock
                .read(&mut chunk)
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("REALITY: read failed: {e}")))?;
            if n == 0 {
                return Ok(false);
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Shuts down the underlying TCP connection.
    pub async fn close(&mut self) {
        let _ = self.sock.shutdown().await;
    }
}

/// RFC-015 §4.3: the client stream is a first-class `AsyncIoStream`, so the
/// universal engine's `VlessOutbound` can carry VLESS over the REALITY
/// session without a separate adapter. Shares the same record sequence
/// state as `read_app`/`write_app` — the two APIs must not be mixed on one
/// connection mid-stream, exactly like any TLS stack's dual APIs.
impl AsyncRead for RealityTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self { sock, suite, inbuf, pending, read, write: _, outbuf: _, auth_key: _ } =
            self.get_mut();
        loop {
            if !pending.is_empty() {
                let n = pending.len().min(out.remaining());
                let data = pending.split_to(n);
                out.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; MAX_RECORD];
            let mut read_buf = tokio::io::ReadBuf::new(&mut chunk);
            match Pin::new(&mut *sock).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if inbuf.is_empty() {
                            return Poll::Ready(Ok(())); // clean EOF
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "REALITY: connection closed mid-record",
                        )));
                    }
                    inbuf.extend_from_slice(read_buf.filled());
                    decrypt_available_records(inbuf, pending, read, *suite)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Self { sock, suite, write, outbuf, .. } = self.get_mut();
        let suite = *suite;
        let chunk_len = buf.len().min(14 * 1024);
        let mut payload = buf[..chunk_len].to_vec();
        payload.push(CT_APPLICATION_DATA);
        let record = seal_record(write, suite, CT_APPLICATION_DATA, &mut payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        outbuf.extend_from_slice(&record);
        while !outbuf.is_empty() {
            match Pin::new(&mut *sock).poll_write(cx, outbuf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "REALITY: socket write of zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    outbuf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self { sock, outbuf, .. } = self.get_mut();
        while !outbuf.is_empty() {
            match Pin::new(&mut *sock).poll_write(cx, outbuf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "REALITY: socket write of zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    outbuf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut *sock).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().sock).poll_shutdown(cx)
    }
}

/// Decrypts every complete record buffered in `inbuf` into `pending`.
/// Shared by the async `read_app` path and the `AsyncRead` poll impl so
/// both directions of the API share one record-sequence state.
fn decrypt_available_records(
    inbuf: &mut BytesMut,
    pending: &mut BytesMut,
    keys: &mut DirectionKeys,
    suite: Suite,
) -> Result<(), ShadowMeshError> {
    loop {
        if inbuf.len() < 5 {
            return Ok(());
        }
        let rec_len = u16::from_be_bytes([inbuf[3], inbuf[4]]) as usize;
        if inbuf.len() < 5 + rec_len {
            return Ok(());
        }
        let mut record = inbuf.split_to(5 + rec_len);
        let content_type = record.first().copied().unwrap_or(0);
        if content_type == CT_CHANGE_CIPHER_SPEC {
            continue;
        }
        let mut ciphertext = record.split_off(5);
        if content_type == CT_ALERT {
            return Err(ShadowMeshError::IoError(format!(
                "REALITY: connection closed by server (alert {})",
                ciphertext.first().copied().unwrap_or(0)
            )));
        }
        if content_type != CT_APPLICATION_DATA {
            return Err(ShadowMeshError::Other(format!(
                "REALITY: unexpected post-handshake record type {content_type}"
            )));
        }
        let key = Suite::aead(suite, &keys.key)?;
        let nonce_bytes = keys.nonce();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| ShadowMeshError::Other("REALITY: nonce failed".into()))?;
        let plain = key
            .open_in_place(nonce, Aad::from(record.as_ref()), &mut ciphertext)
            .map_err(|_| ShadowMeshError::Other("REALITY: record decryption failed".into()))?;
        // Strip zero padding; last byte is the inner content type.
        let mut end = plain.len();
        while end > 0 && plain[end - 1] == 0 {
            end -= 1;
        }
        let inner_type = if end > 0 { plain[end - 1] } else { 0 };
        match inner_type {
            CT_APPLICATION_DATA => {
                pending.extend_from_slice(&plain[..end.saturating_sub(1)]);
            }
            CT_HANDSHAKE => {
                // Post-handshake messages (NewSessionTicket etc.): skipped.
                if plain.first() == Some(&HM_NEW_SESSION_TICKET) {
                    debug!("SHADOWMESH_RUST: skipped NewSessionTicket");
                } else {
                    debug!("SHADOWMESH_RUST: skipped handshake msg {:?}", plain.first());
                }
            }
            other => {
                warn!("SHADOWMESH_RUST: ignoring inner content type {other}");
            }
        }
    }
}

/// Builds and sends a plaintext handshake record.
pub(crate) async fn send_record(
    sock: &mut TcpStream,
    content_type: u8,
    msg: &[u8],
) -> Result<(), ShadowMeshError> {
    let mut record = Vec::with_capacity(5 + msg.len());
    record.put_u8(content_type);
    record.extend_from_slice(&[0x03, 0x01]);
    record.put_u16(msg.len() as u16);
    record.extend_from_slice(msg);
    sock.write_all(&record)
        .await
        .map_err(|e| ShadowMeshError::IoError(format!("REALITY: write failed: {e}")))?;
    Ok(())
}

/// Reads one plaintext handshake record (the ServerHello), skipping CCS.
/// `buf` is caller-owned so over-read bytes survive into the flight reads.
async fn read_plaintext_handshake_record(
    sock: &mut TcpStream,
    buf: &mut BytesMut,
) -> Result<Vec<u8>, ShadowMeshError> {
    loop {
        if buf.len() >= 5 {
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + rec_len {
                let mut record = buf.split_to(5 + rec_len);
                let content_type = record.first().copied().unwrap_or(0);
                let body = record.split_off(5);
                if content_type == CT_CHANGE_CIPHER_SPEC {
                    continue;
                }
                if content_type == CT_ALERT {
                    let desc = body.get(1).copied().unwrap_or(0);
                    return Err(ShadowMeshError::Other(format!(
                        "REALITY: server rejected handshake with alert {desc} \
                         (authentication failure — check public key and short_id)"
                    )));
                }
                if content_type != CT_HANDSHAKE {
                    return Err(ShadowMeshError::Other(format!(
                        "REALITY: expected ServerHello, got record type {content_type}"
                    )));
                }
                return Ok(body.to_vec());
            }
        }
        let mut chunk = [0u8; MAX_RECORD];
        let n = sock
            .read(&mut chunk)
            .await
            .map_err(|e| ShadowMeshError::IoError(format!("REALITY: read failed: {e}")))?;
        if n == 0 {
            return Err(ShadowMeshError::Other(
                "REALITY: connection closed during handshake".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads and decrypts one encrypted record using the server handshake keys,
/// skipping CCS. Returns (inner content type, plaintext).
async fn read_encrypted_record(
    sock: &mut TcpStream,
    buf: &mut BytesMut,
    keys: &mut DirectionKeys,
    suite: Suite,
) -> Result<(u8, Vec<u8>), ShadowMeshError> {
    loop {
        if buf.len() >= 5 {
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + rec_len {
                let mut record = buf.split_to(5 + rec_len);
                let content_type = record.first().copied().unwrap_or(0);
                let mut ciphertext = record.split_off(5);
                if content_type == CT_CHANGE_CIPHER_SPEC {
                    continue;
                }
                let key = Suite::aead(suite, &keys.key)?;
                let nonce_bytes = keys.nonce();
                let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
                    .map_err(|_| ShadowMeshError::Other("REALITY: nonce failed".into()))?;
                let plain = key
                    .open_in_place(nonce, Aad::from(record.as_ref()), &mut ciphertext)
                    .map_err(|_| {
                    ShadowMeshError::Other("REALITY: handshake record decryption failed".into())
                })?;
                let mut end = plain.len();
                while end > 0 && plain[end - 1] == 0 {
                    end -= 1;
                }
                let inner_type = if end > 0 { plain[end - 1] } else { 0 };
                return Ok((inner_type, plain[..end.saturating_sub(1)].to_vec()));
            }
        }
        let mut chunk = [0u8; MAX_RECORD];
        let n = sock
            .read(&mut chunk)
            .await
            .map_err(|e| ShadowMeshError::IoError(format!("REALITY: read failed: {e}")))?;
        if n == 0 {
            return Err(ShadowMeshError::Other(
                "REALITY: connection closed during handshake".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Encrypts `payload` (inner content type already appended as the last byte)
/// into a full TLS 1.3 record. AAD is the record header with the real length.
pub(crate) fn seal_record(
    keys: &mut DirectionKeys,
    suite: Suite,
    outer_type: u8,
    payload: &mut [u8],
) -> Result<Vec<u8>, ShadowMeshError> {
    let key = Suite::aead(suite, &keys.key)?;
    let nonce_bytes = keys.nonce();
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| ShadowMeshError::Other("REALITY: nonce failed".into()))?;
    let sealed_len = payload.len() + 16; // + AEAD tag
    let header = [outer_type, 0x03, 0x03, (sealed_len >> 8) as u8, (sealed_len & 0xff) as u8];
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(header.as_ref()), payload)
        .map_err(|_| ShadowMeshError::Other("REALITY: record seal failed".into()))?;
    let mut record = Vec::with_capacity(5 + sealed_len);
    record.put_u8(outer_type);
    record.extend_from_slice(&[0x03, 0x03]);
    record.put_u16(sealed_len as u16);
    record.extend_from_slice(payload);
    record.extend_from_slice(tag.as_ref());
    Ok(record)
}

/// Parses ServerHello; returns (suite, server x25519 key share).
fn parse_server_hello(msg: &[u8]) -> Result<(Suite, Vec<u8>), ShadowMeshError> {
    // msg: [type 1][len 3][legacy_ver 2][random 32][sid_len 1][sid..][cipher 2][comp 1][ext_len 2][exts]
    if msg.first() != Some(&0x02) {
        return Err(ShadowMeshError::Other("REALITY: expected ServerHello message".into()));
    }
    let mut pos = 4 + 2 + 32;
    let sid_len =
        *msg.get(pos).ok_or_else(|| ShadowMeshError::Other("REALITY: short ServerHello".into()))?
            as usize;
    pos += 1 + sid_len;
    pos += 2; // cipher suite (parsed from the same position below)
    let suite = Suite::from_code(u16::from_be_bytes([
        *msg.get(pos - 2)
            .ok_or_else(|| ShadowMeshError::Other("REALITY: short ServerHello".into()))?,
        *msg.get(pos - 1)
            .ok_or_else(|| ShadowMeshError::Other("REALITY: short ServerHello".into()))?,
    ]))?;
    pos += 1; // compression
    let ext_len = u16::from_be_bytes([
        *msg.get(pos).ok_or_else(|| ShadowMeshError::Other("REALITY: short ServerHello".into()))?,
        *msg.get(pos + 1)
            .ok_or_else(|| ShadowMeshError::Other("REALITY: short ServerHello".into()))?,
    ]) as usize;
    pos += 2;
    let end = (pos + ext_len).min(msg.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let elen = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
        let data = msg.get(pos + 4..pos + 4 + elen).ok_or_else(|| {
            ShadowMeshError::Other("REALITY: truncated ServerHello extension".into())
        })?;
        if ext_type == 0x0033 {
            // server share: [group 2][len 2][data..]
            let group = u16::from_be_bytes([
                *data
                    .first()
                    .ok_or_else(|| ShadowMeshError::Other("REALITY: bad key_share".into()))?,
                *data
                    .get(1)
                    .ok_or_else(|| ShadowMeshError::Other("REALITY: bad key_share".into()))?,
            ]);
            if group != 0x001d {
                return Err(ShadowMeshError::Other(
                    "REALITY: server selected non-x25519 group".into(),
                ));
            }
            let klen = u16::from_be_bytes([
                *data
                    .get(2)
                    .ok_or_else(|| ShadowMeshError::Other("REALITY: bad key_share".into()))?,
                *data
                    .get(3)
                    .ok_or_else(|| ShadowMeshError::Other("REALITY: bad key_share".into()))?,
            ]) as usize;
            let share = data
                .get(4..4 + klen)
                .ok_or_else(|| ShadowMeshError::Other("REALITY: truncated key_share".into()))?;
            return Ok((suite, share.to_vec()));
        }
        pos += 4 + elen;
    }
    Err(ShadowMeshError::Other("REALITY: ServerHello missing key_share".into()))
}

/// Parses the server Certificate message, verifies the REALITY temp-cert
/// (single Ed25519 cert whose signature is HMAC-SHA512(auth_key, pubkey)),
/// and returns (ed25519_pub, cert_der).
fn parse_and_verify_temp_cert(
    msg: &[u8],
    auth_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), ShadowMeshError> {
    let short = || ShadowMeshError::Other("REALITY: truncated Certificate message".into());
    let mut pos = 4;
    pos += 1; // certificate_request_context (must be empty from server)
    let count = u32::from_be_bytes([
        0,
        *msg.get(pos).ok_or_else(short)?,
        *msg.get(pos + 1).ok_or_else(short)?,
        *msg.get(pos + 2).ok_or_else(short)?,
    ]) as usize;
    pos += 3;
    if count != 1 {
        // A full chain (e.g. the genuine dl.google.com certificate) means the
        // REALITY server rejected our ClientHello and proxied us to the
        // masquerade target.
        return Err(ShadowMeshError::Other(
            "REALITY handshake failed: server presented the real camouflage certificate \
             (authentication rejected — check server public key, short_id and SNI)"
                .into(),
        ));
    }
    let cert_len = u32::from_be_bytes([
        0,
        *msg.get(pos).ok_or_else(short)?,
        *msg.get(pos + 1).ok_or_else(short)?,
        *msg.get(pos + 2).ok_or_else(short)?,
    ]) as usize;
    pos += 3;
    let der = msg.get(pos..pos + cert_len).ok_or_else(short)?;

    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| ShadowMeshError::Other(format!("REALITY: certificate parse failed: {e}")))?;

    // Ed25519 SPKI check (OID 1.3.101.112) + extract the raw 32-byte public key.
    let spki = &cert.tbs_certificate.subject_pki;
    let is_ed25519 = spki.algorithm.algorithm.to_id_string() == "1.3.101.112";
    let pub_key = spki.subject_public_key.data.to_vec();
    if !is_ed25519 || pub_key.len() != 32 {
        return Err(ShadowMeshError::Other(
            "REALITY handshake failed: server did not present a REALITY temp certificate \
             (authentication rejected — check server public key, short_id and SNI)"
                .into(),
        ));
    }

    let sig = cert.signature_value.data.to_vec();
    let expected = hmac::sign(&hmac::Key::new(HMAC_SHA512, auth_key), &pub_key);
    if sig.as_slice() != expected.as_ref() {
        return Err(ShadowMeshError::Other(
            "REALITY handshake failed: temp-certificate HMAC mismatch \
             (server is not the REALITY endpoint for this key)"
                .into(),
        ));
    }
    Ok((pub_key, der.to_vec()))
}

/// Verifies the Ed25519 CertificateVerify over the RFC 8446 §4.4.3 message.
fn verify_certificate_verify(
    msg: &[u8],
    pub_key: &[u8],
    transcript: &digest::Context,
) -> Result<(), ShadowMeshError> {
    if msg.first() != Some(&HM_CERTIFICATE_VERIFY) {
        return Err(ShadowMeshError::Other("REALITY: expected CertificateVerify".into()));
    }
    if msg.len() < 8 {
        return Err(ShadowMeshError::Other("REALITY: truncated CertificateVerify".into()));
    }
    let sig_alg = u16::from_be_bytes([msg[4], msg[5]]);
    if sig_alg != 0x0807 {
        return Err(ShadowMeshError::Other(format!(
            "REALITY: unexpected certificate verify algorithm {sig_alg:#06x}"
        )));
    }
    let sig_len = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let sig = msg
        .get(8..8 + sig_len)
        .ok_or_else(|| ShadowMeshError::Other("REALITY: truncated CertificateVerify".into()))?;

    let mut signed = Vec::with_capacity(64 + 34 + 32);
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript.clone().finish().as_ref());
    UnparsedPublicKey::new(&ED25519, pub_key)
        .verify(&signed, sig)
        .map_err(|_| ShadowMeshError::Other("REALITY: CertificateVerify signature invalid".into()))
}

/// Verifies the server Finished MAC.
fn verify_server_finished(
    msg: &[u8],
    s_hs_traffic: &[u8],
    suite: Suite,
    transcript: &digest::Context,
) -> Result<(), ShadowMeshError> {
    if msg.first() != Some(&HM_FINISHED) {
        return Err(ShadowMeshError::Other("REALITY: expected Finished".into()));
    }
    let hash_len = suite.hash().output_len();
    let finished_key = hkdf_expand_label(suite, s_hs_traffic, b"", b"finished", &[], hash_len);
    let expected = hmac::sign(
        &hmac::Key::new(*suite.hmac_alg(), &finished_key),
        transcript.clone().finish().as_ref(),
    );
    let verify_data = msg.get(4..).unwrap_or(&[]);
    if verify_data != expected.as_ref() {
        return Err(ShadowMeshError::Other("REALITY: server Finished MAC invalid".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_rfc5869_vector() {
        // RFC 5869 Appendix A.1 (SHA-256).
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = hkdf_extract(&HMAC_SHA256, &salt, &ikm);
        assert_eq!(
            hex::encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(&HMAC_SHA256, &prk, &info, 42);
        assert_eq!(
            hex::encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_expand_label_is_deterministic_and_len_bound() {
        let secret = [0xabu8; 32];
        let a = hkdf_expand_label(
            Suite::Aes128GcmSha256,
            &secret,
            b"",
            b"c hs traffic",
            &[0u8; 32],
            32,
        );
        let b = hkdf_expand_label(
            Suite::Aes128GcmSha256,
            &secret,
            b"",
            b"c hs traffic",
            &[0u8; 32],
            32,
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // Different context must change the output (transcript binding).
        let c = hkdf_expand_label(
            Suite::Aes128GcmSha256,
            &secret,
            b"",
            b"c hs traffic",
            &[1u8; 32],
            32,
        );
        assert_ne!(a, c);
    }

    #[test]
    fn test_direction_keys_nonce_xors_sequence() {
        let secret = [0x42u8; 32];
        let suite = Suite::Aes128GcmSha256;
        let traffic = hkdf_expand_label(suite, &secret, b"", b"c hs traffic", &[0u8; 32], 32);
        let mut keys = DirectionKeys::from_traffic_secret(suite, &traffic).unwrap();
        let n0 = keys.nonce();
        let n1 = keys.nonce();
        assert_ne!(n0, n1);
        assert_eq!(n0[..11], n1[..11]);
        assert_ne!(n0[11], n1[11]);
    }

    #[test]
    fn test_suite_codes() {
        assert_eq!(Suite::from_code(0x1301).unwrap(), Suite::Aes128GcmSha256);
        assert_eq!(Suite::from_code(0x1302).unwrap(), Suite::Aes256GcmSha384);
        assert_eq!(Suite::from_code(0x1303).unwrap(), Suite::ChaCha20Poly1305Sha256);
        assert!(Suite::from_code(0x1300).is_err());
    }

    #[test]
    fn test_parse_server_hello_rejects_garbage() {
        assert!(parse_server_hello(&[0x0b, 0x00, 0x00]).is_err());
        assert!(parse_server_hello(&[]).is_err());
    }

    #[test]
    fn test_seal_record_roundtrip() {
        let secret = [0x11u8; 32];
        let suite = Suite::Aes128GcmSha256;
        let traffic = hkdf_expand_label(suite, &secret, b"", b"c ap traffic", &[0u8; 32], 32);
        let mut w = DirectionKeys::from_traffic_secret(suite, &traffic).unwrap();
        let mut r = DirectionKeys::from_traffic_secret(suite, &traffic).unwrap();

        let mut payload = b"hello tunnel".to_vec();
        payload.push(CT_APPLICATION_DATA);
        let record = seal_record(&mut w, suite, CT_APPLICATION_DATA, &mut payload).unwrap();

        // Decrypt side (mirrors fill_and_decrypt)
        let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), 5 + rec_len);
        let record_copy = bytes::BytesMut::from(&record[..]);
        let mut record_copy = record_copy;
        let header = record_copy.split_to(5);
        let mut ct = record_copy;
        let key = Suite::aead(suite, &r.key).unwrap();
        let nonce_bytes = r.nonce();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let plain = key.open_in_place(nonce, Aad::from(header.as_ref()), &mut ct).unwrap();

        // Strip inner content type (last byte)
        assert_eq!(plain[plain.len() - 1], CT_APPLICATION_DATA);
        assert_eq!(&plain[..plain.len() - 1], b"hello tunnel");
    }
}
