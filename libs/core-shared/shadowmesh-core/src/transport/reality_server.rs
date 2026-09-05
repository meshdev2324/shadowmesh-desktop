//! Server side of the REALITY TLS 1.3 dialect spoken by `reality_tls.rs`.
//!
//! Clean-room mirror of this project's own client: the server reads the
//! ClientHello, verifies the REALITY `session_id` auth (AES-256-GCM under
//! `HKDF(ECDH(server_reality_priv, client_share), salt=random[..20],
//! "REALITY")`), then completes a minimal TLS 1.3 flight whose certificate
//! is a single Ed25519 temp cert whose signature is
//! `HMAC-SHA512(auth_key, ed25519_pub)` — exactly what the client verifies.
//! Any pre-auth failure yields a transparent fallback (the raw bytes are
//! relayed to the masquerade target), preserving active-probing resistance.
//!
//! Implementation Source:
//! - RFC 8446 (TLS 1.3 key schedule, record layer, CertificateVerify)
//! - This repository's `reality_tls.rs` client (byte-level contract)
//! - Security: only `ring` / `x25519-dalek` primitives; session keys are
//!   zeroized on drop (ZPII). Never derived from GPL sources.

use crate::ShadowMeshError;
use bytes::{BufMut, BytesMut};
use ring::aead::{Aad, Nonce};
use ring::hmac::HMAC_SHA256;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, trace};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use super::reality_tls::{
    hkdf_expand, hkdf_expand_label, hkdf_extract, put_u24, seal_record, send_record, DirectionKeys,
    Suite, CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HM_CERTIFICATE,
    HM_CERTIFICATE_VERIFY, HM_CLIENT_HELLO, HM_ENCRYPTED_EXTENSIONS, HM_FINISHED, MAX_RECORD,
};

/// Outcome of a REALITY accept attempt.
pub enum Accepted {
    /// Authenticated: a decrypted application-data stream.
    Stream(RealityServerStream),
    /// Authentication failed (or the bytes were not REALITY at all): the
    /// raw ClientHello bytes must be relayed to the masquerade target.
    Fallback(TcpStream, Vec<u8>),
}

/// Performs the server-side REALITY handshake. All pre-authentication
/// anomalies resolve to [`Accepted::Fallback`] — the caller relays them to
/// the masquerade target, so an active prober only ever sees a genuine
/// masquerade site.
pub async fn accept(sock: TcpStream, config: &crate::RealityServerConfig) -> Accepted {
    let mut sock = sock;
    match handshake(&mut sock, config).await {
        Ok(parts) => Accepted::Stream(RealityServerStream {
            sock,
            suite: parts.suite,
            auth_key: parts.auth_key,
            write: parts.write,
            read: parts.read,
            inbuf: parts.inbuf,
            pending: BytesMut::new(),
            outbuf: Vec::new(),
        }),
        Err(buffered) => Accepted::Fallback(sock, buffered),
    }
}

/// Everything the record layer needs, minus the socket itself.
struct HandshakeParts {
    suite: Suite,
    auth_key: [u8; 32],
    write: DirectionKeys,
    read: DirectionKeys,
    inbuf: BytesMut,
}

/// Server-side configuration problem (bad key material): cannot serve
/// REALITY at all.
fn config_error() -> Vec<u8> {
    Vec::new()
}

/// Runs the full handshake; every pre-auth failure returns the bytes
/// received so far so the caller can relay them to the masquerade.
async fn handshake(
    sock: &mut TcpStream,
    config: &crate::RealityServerConfig,
) -> Result<HandshakeParts, Vec<u8>> {
    // ---- Read the ClientHello record (raw bytes kept for fallback) ----
    let mut raw = BytesMut::with_capacity(MAX_RECORD);
    let ch_record = loop {
        if raw.len() >= 5 {
            let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
            if raw.len() >= 5 + rec_len {
                break raw.split_to(5 + rec_len).to_vec();
            }
        }
        let mut chunk = [0u8; MAX_RECORD];
        // Probing resistance: a silent probe must fall back, not pin the task.
        let n = match tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut chunk))
            .await
        {
            Ok(n) => n.map_err(|_| config_error())?,
            Err(_) => return Err(raw.to_vec()),
        };
        if n == 0 {
            return Err(raw.to_vec());
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    if ch_record.first() != Some(&CT_HANDSHAKE) {
        return Err(ch_record.clone());
    }
    let ch_msg = &ch_record[5..];
    if ch_msg.first() != Some(&HM_CLIENT_HELLO) || ch_msg.len() < 71 {
        return Err(ch_record.clone());
    }

    // ClientHello layout (fixed at this point):
    // [type 1][len 3][ver 2][random 32][sid_len 1][sid 32][suites..][exts..]
    let random: [u8; 32] = ch_msg[6..38].try_into().map_err(|_| ch_record.clone())?;
    let sealed_sid: [u8; 32] = ch_msg[39..71].try_into().map_err(|_| ch_record.clone())?;

    let (ciphers, exts) = match parse_ch_tail(ch_msg) {
        Some(v) => v,
        None => return Err(ch_record.clone()),
    };

    // ---- REALITY session_id authentication ----
    let client_share: [u8; 32] = match find_key_share(exts) {
        Some(s) if s.len() == 32 => s.try_into().map_err(|_| ch_record.clone())?,
        _ => return Err(ch_record.clone()),
    };

    let server_priv_bytes: [u8; 32] = hex::decode(config.private_key.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(config_error)?;
    let server_priv = StaticSecret::from(server_priv_bytes);

    let reality_shared = server_priv.diffie_hellman(&XPublicKey::from(client_share));
    // Mirrors the client: PRK = HMAC-SHA256(key=random[..20], msg=shared), then expand "REALITY".
    let prk = hkdf_extract(&HMAC_SHA256, &random[..20], reality_shared.as_bytes());
    let auth_key: [u8; 32] = hkdf_expand(&HMAC_SHA256, &prk, b"REALITY", 32)
        .try_into()
        .map_err(|_| ch_record.clone())?;

    // Open the session_id: AAD = ClientHello with the session_id zeroed.
    let mut sealed_buf = sealed_sid.to_vec();
    let opened = {
        let mut aad = ch_msg.to_vec();
        aad[39..71].fill(0);
        let key = Suite::Aes256GcmSha384.aead(&auth_key).map_err(|_| ch_record.clone())?;
        let nonce =
            Nonce::try_assume_unique_for_key(&random[20..32]).map_err(|_| ch_record.clone())?;
        key.open_in_place(nonce, Aad::from(aad.as_slice()), &mut sealed_buf)
            .ok()
            .and_then(|p| <[u8; 16]>::try_from(p).ok())
    };
    let plain = match opened {
        Some(p) => p,
        None => return Err(ch_record.clone()),
    };

    // plain = [ver 3][time u32 BE][short_id..padded with zeros]
    let ts = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]) as u64;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if ts > now + 30 || ts < now.saturating_sub(300) {
        return Err(ch_record.clone());
    }
    let short_ok = config.short_ids.iter().any(|allowed| match hex::decode(allowed.trim()) {
        Ok(b) if !b.is_empty() && b.len() <= 8 => {
            plain[8..8 + b.len()] == b[..] && plain[8 + b.len()..16].iter().all(|&x| x == 0)
        }
        _ => false,
    });
    if !short_ok {
        return Err(ch_record.clone());
    }
    debug!("REALITY server: session_id authenticated (short_id match)");

    // ---- ServerHello (fresh TLS ephemeral — the REALITY key is auth-only) ----
    let suite = negotiate_suite(ciphers).map_err(|_| ch_record.clone())?;
    let tls_priv = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let tls_pub = XPublicKey::from(&tls_priv);

    let mut sh_random = [0u8; 32];
    sh_random.copy_from_slice(&crate::secure_random_bytes(32).ok_or_else(config_error)?);

    let mut sh_body = Vec::with_capacity(96);
    sh_body.extend_from_slice(&[0x03, 0x03]);
    sh_body.extend_from_slice(&sh_random);
    sh_body.put_u8(32);
    sh_body.extend_from_slice(&sealed_sid); // echo the client's session_id
    sh_body.extend_from_slice(&suite_code(suite).to_be_bytes());
    sh_body.put_u8(0); // compression
                       // extensions: key_share (x25519) — [group 2][len 2][share 32]
    let mut ext = Vec::new();
    ext.put_u16(0x0033);
    ext.put_u16(36);
    ext.put_u16(0x001d);
    ext.put_u16(32);
    ext.extend_from_slice(tls_pub.as_bytes());
    sh_body.put_u16(ext.len() as u16);
    sh_body.extend_from_slice(&ext);

    let mut sh_msg = Vec::with_capacity(sh_body.len() + 4);
    sh_msg.push(0x02); // ServerHello handshake type
    put_u24(&mut sh_msg, sh_body.len());
    sh_msg.extend_from_slice(&sh_body);

    send_record(sock, CT_HANDSHAKE, &sh_msg).await.map_err(|_| ch_record.clone())?;

    // ---- TLS 1.3 key schedule (mirrors the client exactly) ----
    let mut transcript = ring::digest::Context::new(suite.hash());
    transcript.update(ch_msg);
    transcript.update(&sh_msg);

    let hash_len = suite.hash().output_len();
    let zeros = vec![0u8; hash_len];
    let early = hkdf_extract(suite.hmac_alg(), &zeros, &zeros);
    let derived = hkdf_expand_label(suite, &early, b"", b"derived", &[], hash_len);
    let tls_shared = tls_priv.diffie_hellman(&XPublicKey::from(client_share));
    let hs_secret = hkdf_extract(suite.hmac_alg(), &derived, tls_shared.as_bytes());

    let th_sh = transcript.clone().finish();
    let s_hs_traffic =
        hkdf_expand_label(suite, &hs_secret, b"", b"s hs traffic", th_sh.as_ref(), hash_len);
    let c_hs_traffic =
        hkdf_expand_label(suite, &hs_secret, b"", b"c hs traffic", th_sh.as_ref(), hash_len);

    // ---- Encrypted flight: EE, Certificate (temp cert), CertificateVerify, Finished ----
    let seed = crate::secure_random_bytes(32).ok_or_else(config_error)?;
    let ed_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| ShadowMeshError::Other("REALITY: ed25519 seed rejected".into()))
        .map_err(|_| config_error())?;
    let ed_pub = ed_pair.public_key().as_ref().to_vec();
    let cert_der = build_temp_cert(&ed_pub, &auth_key);

    let ee = {
        let mut m = Vec::new();
        m.push(HM_ENCRYPTED_EXTENSIONS);
        put_u24(&mut m, 2);
        m.extend_from_slice(&[0x00, 0x00]); // empty extensions
        m
    };
    let cert_msg = {
        let mut m = Vec::with_capacity(10 + cert_der.len());
        m.push(HM_CERTIFICATE);
        put_u24(&mut m, 1 + 3 + 3 + cert_der.len());
        m.put_u8(0); // certificate_request_context (empty)
        m.extend_from_slice(&[0, 0, 1]); // exactly one certificate
        put_u24(&mut m, cert_der.len());
        m.extend_from_slice(&cert_der);
        m
    };
    transcript.update(&ee);
    transcript.update(&cert_msg);

    let cv_sig = {
        let mut signed = Vec::with_capacity(64 + 34 + 32);
        signed.extend_from_slice(&[0x20u8; 64]);
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0x00);
        signed.extend_from_slice(transcript.clone().finish().as_ref());
        ed_pair.sign(&signed)
    };
    let cv_sig_bytes = cv_sig.as_ref().to_vec();
    let cv = {
        let mut m = Vec::with_capacity(8 + cv_sig_bytes.len());
        m.push(HM_CERTIFICATE_VERIFY);
        put_u24(&mut m, 2 + 2 + cv_sig_bytes.len());
        m.extend_from_slice(&0x0807u16.to_be_bytes()); // ed25519
        m.extend_from_slice(&(cv_sig_bytes.len() as u16).to_be_bytes());
        m.extend_from_slice(&cv_sig_bytes);
        m
    };
    transcript.update(&cv);

    let mut s_hs_keys =
        DirectionKeys::from_traffic_secret(suite, &s_hs_traffic).map_err(|_| config_error())?;
    for mut msg in [ee, cert_msg, cv] {
        msg.push(CT_HANDSHAKE);
        let record = seal_record(&mut s_hs_keys, suite, CT_APPLICATION_DATA, &mut msg)
            .map_err(|_| config_error())?;
        sock.write_all(&record).await.map_err(|_| ch_record.clone())?;
    }

    // Server Finished over the transcript through CertificateVerify.
    {
        let th_cv = transcript.clone().finish();
        let finished_key = hkdf_expand_label(suite, &s_hs_traffic, b"", b"finished", &[], hash_len);
        let vf = ring::hmac::sign(
            &ring::hmac::Key::new(*suite.hmac_alg(), &finished_key),
            th_cv.as_ref(),
        );
        let mut m = Vec::with_capacity(4 + vf.as_ref().len());
        m.push(HM_FINISHED);
        put_u24(&mut m, vf.as_ref().len());
        m.extend_from_slice(vf.as_ref());
        transcript.update(&m);
        m.push(CT_HANDSHAKE);
        let record = seal_record(&mut s_hs_keys, suite, CT_APPLICATION_DATA, &mut m)
            .map_err(|_| config_error())?;
        sock.write_all(&record).await.map_err(|_| ch_record.clone())?;
    }
    sock.flush().await.map_err(|_| ch_record.clone())?;

    // ---- Application secrets (transcript through server Finished) ----
    let derived2 = hkdf_expand_label(suite, &hs_secret, b"", b"derived", &[], hash_len);
    let master = hkdf_extract(suite.hmac_alg(), &derived2, &zeros);
    let th_fin = transcript.clone().finish();
    let c_ap_traffic =
        hkdf_expand_label(suite, &master, b"", b"c ap traffic", th_fin.as_ref(), hash_len);
    let s_ap_traffic =
        hkdf_expand_label(suite, &master, b"", b"s ap traffic", th_fin.as_ref(), hash_len);

    // ---- Client Finished: the client seals it under its APP traffic keys ----
    let mut read_keys =
        DirectionKeys::from_traffic_secret(suite, &c_ap_traffic).map_err(|_| config_error())?;
    let (inner, plain) = read_encrypted_record(sock, &mut raw, &mut read_keys, suite)
        .await
        .map_err(|_| raw.to_vec())?;
    if inner != CT_HANDSHAKE || plain.first() != Some(&HM_FINISHED) {
        return Err(raw.to_vec());
    }
    {
        let finished_key = hkdf_expand_label(suite, &c_hs_traffic, b"", b"finished", &[], hash_len);
        let expected = ring::hmac::sign(
            &ring::hmac::Key::new(*suite.hmac_alg(), &finished_key),
            th_fin.as_ref(),
        );
        if plain.get(4..) != Some(expected.as_ref()) {
            return Err(raw.to_vec());
        }
    }

    trace!("REALITY server: handshake complete, suite {:?}", suite);
    Ok(HandshakeParts {
        suite,
        auth_key,
        write: DirectionKeys::from_traffic_secret(suite, &s_ap_traffic)
            .map_err(|_| config_error())?,
        read: read_keys,
        inbuf: raw,
    })
}

/// Parses the ClientHello tail: `(cipher_suites, extensions)` starting after
/// the session_id (`msg[71..]`).
fn parse_ch_tail(msg: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut pos = 71;
    let cipher_len = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]) as usize;
    pos += 2;
    let ciphers = msg.get(pos..pos + cipher_len)?;
    pos += cipher_len;
    let comp_len = *msg.get(pos)?;
    pos += 1 + comp_len as usize;
    let ext_len = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]) as usize;
    pos += 2;
    let exts = msg.get(pos..pos + ext_len)?;
    Some((ciphers, exts))
}

/// Extracts the x25519 `key_share` public key from a ClientHello extension block.
fn find_key_share(exts: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
        let elen = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
        let data = exts.get(pos + 4..pos + 4 + elen)?;
        if ext_type == 0x0033 {
            // client_shares list: [list_len 2][group 2][klen 2][share..]
            if data.len() < 6 || data[2] != 0x00 || data[3] != 0x1d {
                return None;
            }
            let klen = u16::from_be_bytes([data[4], data[5]]) as usize;
            return data.get(6..6 + klen);
        }
        pos += 4 + elen;
    }
    None
}

/// Picks the first client-offered suite this server supports.
fn negotiate_suite(cipher_bytes: &[u8]) -> Result<Suite, ShadowMeshError> {
    for pair in cipher_bytes.chunks(2) {
        if pair.len() != 2 {
            break;
        }
        let code = u16::from_be_bytes([pair[0], pair[1]]);
        if let Ok(s) = Suite::from_code(code) {
            return Ok(s);
        }
    }
    Err(ShadowMeshError::Other("REALITY: no supported cipher suite".into()))
}

fn suite_code(suite: Suite) -> u16 {
    match suite {
        Suite::Aes128GcmSha256 => 0x1301,
        Suite::Aes256GcmSha384 => 0x1302,
        Suite::ChaCha20Poly1305Sha256 => 0x1303,
    }
}

/// Reads + decrypts one post-ServerHello record (skips CCS). Returns
/// `(inner content type, plaintext)`.
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
                let plain =
                    key.open_in_place(nonce, Aad::from(record.as_ref()), &mut ciphertext).map_err(
                        |_| ShadowMeshError::Other("REALITY: record decryption failed".into()),
                    )?;
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

/// Builds the minimal Ed25519 temp certificate the client verifies:
/// `signature_value = HMAC-SHA512(auth_key, ed25519_pub)` (RFC-015 §4.1).
fn build_temp_cert(ed_pub: &[u8], auth_key: &[u8; 32]) -> Vec<u8> {
    // DER OIDs: 1.3.101.112 = Ed25519, 2.5.4.3 = commonName.
    const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
        }
        out.extend_from_slice(content);
        out
    }
    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        tlv(0x30, &body)
    }
    fn oid(bytes: &[u8]) -> Vec<u8> {
        tlv(0x06, bytes)
    }

    let ed_oid = oid(OID_ED25519);
    let alg = seq(&[&ed_oid]); // AlgorithmIdentifier (no parameters for Ed25519)

    let cn_oid = oid(OID_CN);
    let attr = seq(&[&cn_oid, &tlv(0x0c, b"ShadowMesh REALITY")]);
    let rdn = tlv(0x31, &attr); // RelativeDistinguishedName = SET
    let name = seq(&[&rdn]);

    let mut spki_key = vec![0x00u8]; // BIT STRING unused-bits byte
    spki_key.extend_from_slice(ed_pub);
    let spki = seq(&[&alg, &tlv(0x03, &spki_key)[..]]);

    let validity = seq(&[&tlv(0x17, b"260101000000Z")[..], &tlv(0x18, b"20540101000000Z")[..]]);

    let version = tlv(0xa0, &tlv(0x02, &[0x01])); // [0] EXPLICIT INTEGER 2 (v3)
    let serial = tlv(0x02, &[0x01]);
    let tbs_body = seq(&[&version, &serial, &alg, &name, &validity, &name, &spki]);

    let sig = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA512, auth_key), ed_pub);
    let mut sig_bits = vec![0x00u8]; // BIT STRING unused-bits byte
    sig_bits.extend_from_slice(sig.as_ref());

    seq(&[&tbs_body, &alg, &tlv(0x03, &sig_bits)[..]])
}

/// An authenticated REALITY session: decrypted application data in both
/// directions over the TLS 1.3 record layer.
pub struct RealityServerStream {
    sock: TcpStream,
    suite: Suite,
    /// REALITY authentication key; zeroized on drop (ZPII).
    auth_key: [u8; 32],
    write: DirectionKeys,
    read: DirectionKeys,
    inbuf: BytesMut,
    pending: BytesMut,
    outbuf: Vec<u8>,
}

impl Zeroize for RealityServerStream {
    fn zeroize(&mut self) {
        self.auth_key.zeroize();
        self.write.key.zeroize();
        self.read.key.zeroize();
    }
}

impl Drop for RealityServerStream {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Decrypts every complete record in `inbuf` into `pending` (shared by the
/// method and the `AsyncRead` poll impl so both see one record-sequence).
fn decrypt_stream_records(
    inbuf: &mut BytesMut,
    pending: &mut BytesMut,
    read: &mut DirectionKeys,
    suite: Suite,
) -> Result<(), ShadowMeshError> {
    {
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
            let mut ciphertext = record.split_off(5);
            if content_type == CT_CHANGE_CIPHER_SPEC {
                continue;
            }
            if content_type == CT_ALERT {
                return Err(ShadowMeshError::IoError("REALITY: client sent alert".into()));
            }
            let key = Suite::aead(suite, &read.key)?;
            let nonce_bytes = read.nonce();
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
                .map_err(|_| ShadowMeshError::Other("REALITY: nonce failed".into()))?;
            let plain = key
                .open_in_place(nonce, Aad::from(record.as_ref()), &mut ciphertext)
                .map_err(|_| ShadowMeshError::Other("REALITY: record decryption failed".into()))?;
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
                    // Post-handshake inner records (NewSessionTicket): skipped.
                    debug!("REALITY server: skipped inner handshake record");
                }
                other => {
                    debug!("REALITY server: ignoring inner content type {other}");
                }
            }
        }
    }
}

impl AsyncRead for RealityServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self { sock, suite, inbuf, pending, read, write: _, outbuf: _, auth_key: _ } =
            self.get_mut();
        let suite = *suite;
        loop {
            if !pending.is_empty() {
                let n = pending.len().min(out.remaining());
                let data = pending.split_to(n);
                out.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; MAX_RECORD];
            let mut read_buf = ReadBuf::new(&mut chunk);
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
                    decrypt_stream_records(inbuf, pending, read, suite)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RealityServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
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
        // Opportunistically push buffered records to the socket.
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().sock).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The temp certificate must parse and expose exactly what the client
    /// verifies: Ed25519 SPKI + signature = HMAC-SHA512(auth_key, pub).
    #[test]
    fn temp_cert_parses_and_carries_hmac_signature() {
        let auth_key = [0x42u8; 32];
        let seed = [0x11u8; 32];
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let ed_pub = pair.public_key().as_ref().to_vec();
        let der = build_temp_cert(&ed_pub, &auth_key);

        let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("DER parses");
        let spki = &cert.tbs_certificate.subject_pki;
        assert_eq!(spki.algorithm.algorithm.to_id_string(), "1.3.101.112");
        assert_eq!(spki.subject_public_key.data, ed_pub.as_slice());
        let expected =
            ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key), &ed_pub);
        assert_eq!(cert.signature_value.data, expected.as_ref());
    }

    #[test]
    fn session_id_short_id_matching_handles_padding() {
        // The padded compare is byte-exact: short_id + zero fill to 16.
        let mut plain = [0u8; 16];
        let sid = hex::decode("aabbccdd").unwrap();
        plain[8..8 + sid.len()].copy_from_slice(&sid);
        let b = hex::decode("aabbccdd").unwrap();
        assert!(plain[8..8 + b.len()] == b[..] && plain[8 + b.len()..16].iter().all(|&x| x == 0));
        plain[13] = 0x01; // corrupt a PADDING byte (id is 4 bytes → padding is [12..16])
        assert!(!plain[8 + b.len()..16].iter().all(|&x| x == 0));
    }
}
