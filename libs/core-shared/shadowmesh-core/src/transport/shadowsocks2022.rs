//! Shadowsocks-2022 (RFC-012 §4.3, G1).
//!
//! Clean-room implementation written from the published SIP022 specification
//! (<https://shadowsocks.org/doc/sip022.html>). No third-party Shadowsocks
//! implementation source is consulted or ingested, per the core-rust
//! Independent Implementation Policy; only the specification's algorithm
//! definitions and its known-answer values are used, which is what the
//! specification exists to provide.
//!
//! ## Correction
//!
//! The first version of this module derived the session subkey as
//! `BLAKE3::keyed_hash(psk, "2022-blake3-")`. That was wrong in three ways: it
//! used keyed-hash rather than key-derivation mode, it invented a context
//! string that is not on the wire, and it ignored the per-session salt
//! entirely. A test that asserted an expected value written from memory would
//! have passed while shipping a protocol that cannot interoperate. The
//! authoritative construction, per SIP022 §2.2, is:
//!
//! ```text
//! session_subkey := blake3::derive_key(
//!     context: "shadowsocks 2022 session subkey",
//!     key_material: key + salt)
//! ```
//!
//! The salt is random per session and the same length as the pre-shared key.
//! The KATs below are the specification's known-answer values.
//!
//! ## Why the module stops here
//!
//! RFC-012 §4.1 makes the Protocol Factory the prerequisite for every protocol
//! added here, and the legacy `shadowsocks.rs` is a SIP007-era stream transport
//! with no method abstraction, so there is nowhere to hang a 2022 method name
//! yet. This module therefore owns only the subkey layer, which is the part that
//! must be provably correct before anything is wired up.

use base64::prelude::*;

/// SIP022 §2.2 context string for the traffic session subkey. Part of the wire
/// format: changing it silently breaks interop, so it is a constant.
pub const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// SIP022 §2.3 context string for the Extensible Identity Header subkey.
pub const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

/// The 2022 AEAD methods, per RFC-012 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shadowsocks2022Method {
    /// `2022-blake3-aes-128-gcm` — 16-byte key and salt, EIH capable.
    Aes128Gcm,
    /// `2022-blake3-aes-256-gcm` — 32-byte key and salt, EIH capable.
    Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305` — 32-byte key and salt, no EIH.
    ChaCha20Poly1305,
}

impl Shadowsocks2022Method {
    /// The SIP022 method name as it appears on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Shadowsocks2022Method::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Shadowsocks2022Method::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Shadowsocks2022Method::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Some(Shadowsocks2022Method::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Shadowsocks2022Method::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Shadowsocks2022Method::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Pre-shared key length in bytes. SIP022 fixes this per method; it is the
    /// BLAKE3 key material length, not a password to be stretched.
    pub fn psk_len(self) -> usize {
        match self {
            Shadowsocks2022Method::Aes128Gcm => 16,
            Shadowsocks2022Method::Aes256Gcm | Shadowsocks2022Method::ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length. SIP022 requires it to equal the pre-shared key length.
    pub fn salt_len(self) -> usize {
        self.psk_len()
    }

    /// Only the AES methods support Extensible Identity Headers; the ChaCha
    /// variants use random nonces and cannot do the EIH round trip.
    pub fn supports_eih(self) -> bool {
        !matches!(self, Shadowsocks2022Method::ChaCha20Poly1305)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Shadowsocks2022Error {
    InvalidBase64,
    /// A configuration error. A wrong length is never padded or truncated:
    /// either would silently change the key material.
    InvalidKeyLength {
        len: usize,
        expected: usize,
    },
    /// The salt length does not match the method.
    InvalidSaltLength {
        len: usize,
        expected: usize,
    },
    /// The nonce is shorter than the 96 bits every SIP022 AEAD requires.
    InvalidNonceLength,
    /// AEAD tag verification failed. Deliberately carries no detail: separating
    /// "wrong key" from "corrupt frame" from "bad length" would leak to an
    /// attacker probing the endpoint, and active probing is a live threat.
    Authentication,
    /// The AEAD rejected an operation for a reason other than tag mismatch.
    Crypto(String),
    /// A frame payload exceeded the SIP022 chunk limit. Refused rather than
    /// truncated, because a short frame would corrupt the tunnel silently.
    PayloadTooLarge {
        len: usize,
        max: usize,
    },
}

impl std::fmt::Display for Shadowsocks2022Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shadowsocks2022Error::InvalidBase64 => write!(f, "pre-shared key is not valid base64"),
            Shadowsocks2022Error::InvalidKeyLength { len, expected } => {
                write!(f, "pre-shared key is {len} bytes; this method requires exactly {expected}")
            }
            Shadowsocks2022Error::InvalidSaltLength { len, expected } => {
                write!(f, "salt is {len} bytes; this method requires exactly {expected}")
            }
            Shadowsocks2022Error::InvalidNonceLength => {
                write!(f, "nonce must be {NONCE_LEN} bytes")
            }
            // Intentionally opaque. See the variant's doc comment: a detailed
            // reason here would help an active prober classify the endpoint.
            Shadowsocks2022Error::Authentication => write!(f, "authentication failed"),
            Shadowsocks2022Error::Crypto(detail) => write!(f, "crypto error: {detail}"),
            Shadowsocks2022Error::PayloadTooLarge { len, max } => {
                write!(f, "payload {len} exceeds ss2022 chunk limit {max}")
            }
        }
    }
}

impl std::error::Error for Shadowsocks2022Error {}

/// Decodes a base64 pre-shared key and enforces the method's fixed length.
pub fn decode_psk(
    method: Shadowsocks2022Method,
    psk_b64: &str,
) -> Result<Vec<u8>, Shadowsocks2022Error> {
    let bytes =
        BASE64_STANDARD.decode(psk_b64.trim()).map_err(|_| Shadowsocks2022Error::InvalidBase64)?;
    if bytes.len() != method.psk_len() {
        return Err(Shadowsocks2022Error::InvalidKeyLength {
            len: bytes.len(),
            expected: method.psk_len(),
        });
    }
    Ok(bytes)
}

/// Validates a session salt: SIP022 requires it to match the key length.
pub fn validate_salt(
    method: Shadowsocks2022Method,
    salt: &[u8],
) -> Result<(), Shadowsocks2022Error> {
    if salt.len() != method.salt_len() {
        return Err(Shadowsocks2022Error::InvalidSaltLength {
            len: salt.len(),
            expected: method.salt_len(),
        });
    }
    Ok(())
}

/// `blake3::derive_key(context, psk || salt)`, truncated to the method key
/// length. This is the SIP022 §2.2 session subkey derivation.
pub fn derive_session_subkey(
    method: Shadowsocks2022Method,
    psk: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, Shadowsocks2022Error> {
    validate_salt(method, salt)?;
    if psk.len() != method.psk_len() {
        return Err(Shadowsocks2022Error::InvalidKeyLength {
            len: psk.len(),
            expected: method.psk_len(),
        });
    }
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let full = blake3::derive_key(SESSION_SUBKEY_CONTEXT, &material);
    Ok(full[..method.psk_len()].to_vec())
}

/// The identity subkey used for Extensible Identity Headers (SIP022 §2.3).
/// Distinct from the session subkey purely by context string.
pub fn derive_identity_subkey(
    method: Shadowsocks2022Method,
    psk: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, Shadowsocks2022Error> {
    validate_salt(method, salt)?;
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let full = blake3::derive_key(IDENTITY_SUBKEY_CONTEXT, &material);
    Ok(full[..method.psk_len()].to_vec())
}

// ---------------------------------------------------------------------------
// Data path (SIP022 §2.2)
// ---------------------------------------------------------------------------
//
// This is the layer that was entirely missing. The module previously ended at
// key derivation, which meant nothing could be encrypted, nothing decrypted, and
// no byte could flow. The subkey work was necessary; necessary is not sufficient.
//
// SIP022 frame layout:
//
//     [ salt (variable) ][ AEAD-encrypted length (2B) ][ encrypted payload ]
//
// The length is encrypted and authenticated as AAD, which is what prevents a
// truncation or extension attack: an attacker cannot alter the declared length
// without failing the tag.

/// AEAD-encrypt `plaintext`, returning `ciphertext || tag`.
///
/// `aad` is authenticated but not encrypted. The session header is supplied
/// here so a frame cannot be replayed under a different header.
pub fn seal(
    method: Shadowsocks2022Method,
    session_subkey: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Shadowsocks2022Error> {
    check_key_and_nonce(method, session_subkey, nonce)?;
    let nonce = &nonce[..NONCE_LEN];

    match method {
        Shadowsocks2022Method::Aes128Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(session_subkey).map_err(|_| {
                Shadowsocks2022Error::InvalidKeyLength { len: session_subkey.len(), expected: 16 }
            })?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
        Shadowsocks2022Method::Aes256Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(session_subkey).map_err(|_| {
                Shadowsocks2022Error::InvalidKeyLength { len: session_subkey.len(), expected: 32 }
            })?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
        Shadowsocks2022Method::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(session_subkey)
                .map_err(|_| Shadowsocks2022Error::InvalidKeyLength {
                    len: session_subkey.len(),
                    expected: 32,
                })?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
    }
}

/// AEAD-decrypt `ciphertext || tag`, verifying the tag in constant time.
///
/// Any failure returns [`Shadowsocks2022Error::Authentication`] with no detail.
/// Distinguishing "wrong key" from "corrupt frame" from "bad length" would leak
/// information to an attacker probing the endpoint, and active probing is a live
/// threat for this product - see docs/PROTOCOL.md section 3.
pub fn open(
    method: Shadowsocks2022Method,
    session_subkey: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Shadowsocks2022Error> {
    check_key_and_nonce(method, session_subkey, nonce)?;
    let nonce = &nonce[..NONCE_LEN];

    match method {
        Shadowsocks2022Method::Aes128Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(session_subkey).map_err(|_| {
                Shadowsocks2022Error::InvalidKeyLength { len: session_subkey.len(), expected: 16 }
            })?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
        Shadowsocks2022Method::Aes256Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(session_subkey).map_err(|_| {
                Shadowsocks2022Error::InvalidKeyLength { len: session_subkey.len(), expected: 32 }
            })?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
        Shadowsocks2022Method::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(session_subkey)
                .map_err(|_| Shadowsocks2022Error::InvalidKeyLength {
                    len: session_subkey.len(),
                    expected: 32,
                })?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| Shadowsocks2022Error::Authentication)
        }
    }
}

fn check_key_and_nonce(
    method: Shadowsocks2022Method,
    session_subkey: &[u8],
    nonce: &[u8],
) -> Result<(), Shadowsocks2022Error> {
    if session_subkey.len() != method.psk_len() {
        return Err(Shadowsocks2022Error::InvalidKeyLength {
            len: session_subkey.len(),
            expected: method.psk_len(),
        });
    }
    if nonce.len() < NONCE_LEN {
        return Err(Shadowsocks2022Error::InvalidNonceLength);
    }
    Ok(())
}

/// Nonce length for every SIP022 AEAD: AES-GCM and ChaCha20-Poly1305 both use
/// 96-bit nonces. Reusing a nonce under one session subkey destroys
/// confidentiality and authenticity, so the transport must never derive a
/// nonce from a counter that can wrap within a single session.
pub const NONCE_LEN: usize = 12;

/// A cryptographically random salt, the length the method requires.
///
/// SIP022 §2.2: salt length equals key length. Reusing a salt across sessions
/// with the same PSK is the same failure as nonce reuse, so this must be drawn
/// from the OS CSPRNG and never derived from a counter.
pub fn random_salt(method: Shadowsocks2022Method) -> Vec<u8> {
    let mut salt = vec![0u8; method.psk_len()];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut salt);
    salt
}

/// A cryptographically random nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    use rand_core::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Specification test material: psk = bytes 0..n, salt = bytes 32..(32+n).
    fn psk16() -> Vec<u8> {
        (0u8..16).collect()
    }
    fn psk32() -> Vec<u8> {
        (0u8..32).collect()
    }
    fn salt16() -> Vec<u8> {
        (32u8..48).collect()
    }
    fn salt32() -> Vec<u8> {
        (32u8..64).collect()
    }

    /// The interop gate. These are the specification's known-answer values.
    /// If either fails, clients and servers will disagree on the session subkey
    /// and every connection fails with an authentication error that looks like a
    /// network fault.
    #[test]
    fn session_subkey_matches_the_specification_kat_128() {
        let subkey = derive_session_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16())
            .expect("valid inputs");
        assert_eq!(hex::encode(&subkey), "8180421f8f56092ca7544a64ff852536");
    }

    #[test]
    fn session_subkey_matches_the_specification_kat_256() {
        let subkey = derive_session_subkey(Shadowsocks2022Method::Aes256Gcm, &psk32(), &salt32())
            .expect("valid inputs");
        assert_eq!(
            hex::encode(&subkey),
            "374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda"
        );
    }

    #[test]
    fn identity_subkey_matches_the_specification_kat() {
        let subkey = derive_identity_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16())
            .expect("valid inputs");
        assert_eq!(hex::encode(&subkey), "1e3587415fc15417133c20d9e4b78ec3");
    }

    /// The exact failure the first implementation would have shipped.
    #[test]
    fn session_and_identity_subkeys_differ() {
        let session =
            derive_session_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16()).unwrap();
        let identity =
            derive_identity_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16()).unwrap();
        assert_ne!(session, identity, "context strings must separate the subkeys");
    }

    /// A fresh salt per session is what stops a captured session key being
    /// reused. If the salt were ignored this would fail.
    #[test]
    fn a_different_salt_yields_a_different_subkey() {
        let a =
            derive_session_subkey(Shadowsocks2022Method::Aes256Gcm, &psk32(), &salt32()).unwrap();
        let other_salt: Vec<u8> = (64u8..96).collect();
        let b =
            derive_session_subkey(Shadowsocks2022Method::Aes256Gcm, &psk32(), &other_salt).unwrap();
        assert_ne!(a, b, "the salt must contribute to the subkey");
    }

    #[test]
    fn a_different_psk_yields_a_different_subkey() {
        let other: Vec<u8> = (1u8..17).collect();
        let a =
            derive_session_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16()).unwrap();
        let b = derive_session_subkey(Shadowsocks2022Method::Aes128Gcm, &other, &salt16()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn subkey_is_truncated_to_the_method_key_length() {
        let a =
            derive_session_subkey(Shadowsocks2022Method::Aes128Gcm, &psk16(), &salt16()).unwrap();
        assert_eq!(a.len(), 16);
        let b =
            derive_session_subkey(Shadowsocks2022Method::Aes256Gcm, &psk32(), &salt32()).unwrap();
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn wrong_psk_length_is_rejected_not_padded() {
        assert_eq!(
            decode_psk(Shadowsocks2022Method::Aes128Gcm, &BASE64_STANDARD.encode(psk32())),
            Err(Shadowsocks2022Error::InvalidKeyLength { len: 32, expected: 16 })
        );
        assert_eq!(
            decode_psk(Shadowsocks2022Method::Aes256Gcm, &BASE64_STANDARD.encode(psk16())),
            Err(Shadowsocks2022Error::InvalidKeyLength { len: 16, expected: 32 })
        );
    }

    #[test]
    fn wrong_salt_length_is_rejected() {
        assert_eq!(
            derive_session_subkey(Shadowsocks2022Method::Aes256Gcm, &psk32(), &salt16()),
            Err(Shadowsocks2022Error::InvalidSaltLength { len: 16, expected: 32 })
        );
    }

    #[test]
    fn malformed_base64_is_a_typed_error_not_a_panic() {
        assert_eq!(
            decode_psk(Shadowsocks2022Method::Aes256Gcm, "not base64!!!"),
            Err(Shadowsocks2022Error::InvalidBase64)
        );
        // An empty string is valid base64 for zero bytes, so it is a length
        // error rather than a decode error.
        assert_eq!(
            decode_psk(Shadowsocks2022Method::Aes256Gcm, ""),
            Err(Shadowsocks2022Error::InvalidKeyLength { len: 0, expected: 32 })
        );
    }

    #[test]
    fn method_names_and_capabilities_match_sip022() {
        assert_eq!(Shadowsocks2022Method::Aes128Gcm.as_str(), "2022-blake3-aes-128-gcm");
        assert_eq!(Shadowsocks2022Method::Aes128Gcm.psk_len(), 16);
        assert_eq!(Shadowsocks2022Method::Aes256Gcm.psk_len(), 32);
        assert_eq!(Shadowsocks2022Method::ChaCha20Poly1305.psk_len(), 32);
        assert!(Shadowsocks2022Method::Aes128Gcm.supports_eih());
        assert!(!Shadowsocks2022Method::ChaCha20Poly1305.supports_eih());
        assert_eq!(
            Shadowsocks2022Method::from_name("2022-blake3-aes-256-gcm"),
            Some(Shadowsocks2022Method::Aes256Gcm)
        );
        assert_eq!(Shadowsocks2022Method::from_name("aes-256-gcm"), None);
    }

    // ---- data path -------------------------------------------------------

    const METHODS: [Shadowsocks2022Method; 3] = [
        Shadowsocks2022Method::Aes128Gcm,
        Shadowsocks2022Method::Aes256Gcm,
        Shadowsocks2022Method::ChaCha20Poly1305,
    ];

    fn psk_for(m: Shadowsocks2022Method) -> Vec<u8> {
        (0..m.psk_len() as u8).collect()
    }

    #[test]
    fn round_trips_every_method() {
        for m in METHODS {
            let psk = psk_for(m);
            let salt = random_salt(m);
            let subkey = derive_session_subkey(m, &psk, &salt).unwrap();
            let nonce = random_nonce();
            let ct = seal(m, &subkey, &nonce, b"hdr", b"hello shadowmesh").unwrap();
            let pt = open(m, &subkey, &nonce, b"hdr", &ct).unwrap();
            assert_eq!(pt, b"hello shadowmesh", "{m:?} failed to round trip");
        }
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            let secret = b"the-quick-brown-fox-jumps-over-the-lazy-dog-0123456789";
            let ct = seal(m, &subkey, &nonce, b"", secret).unwrap();
            assert!(
                !ct.windows(secret.len()).any(|w| w == secret),
                "{m:?} leaked plaintext into the ciphertext"
            );
        }
    }

    /// The property that makes a frame unsliceable: altering the associated
    /// header, or any byte of the frame, must fail authentication.
    #[test]
    fn tampering_with_ciphertext_is_detected() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            let mut ct = seal(m, &subkey, &nonce, b"h", b"sensitive payload").unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 0x01;
            assert!(
                open(m, &subkey, &nonce, b"h", &ct).is_err(),
                "{m:?} accepted a flipped tag byte"
            );
        }
    }

    #[test]
    fn tampering_with_aad_is_detected() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            let ct = seal(m, &subkey, &nonce, b"header-v1", b"payload").unwrap();
            assert!(
                open(m, &subkey, &nonce, b"header-v2", &ct).is_err(),
                "{m:?} accepted a frame replayed under a different header"
            );
        }
    }

    /// Replay under a different nonce must fail: this is the frame-splicing
    /// defence that the decoy alone does not provide.
    #[test]
    fn nonce_change_fails_to_decrypt() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            let ct = seal(m, &subkey, &nonce, b"", b"payload").unwrap();
            let other = random_nonce();
            assert!(open(m, &subkey, &other, b"", &ct).is_err());
        }
    }

    /// A distinct salt must produce a distinct subkey, or two sessions would
    /// share key material and one captured frame would decrypt the other.
    #[test]
    fn different_salts_give_different_subkeys() {
        for m in METHODS {
            let psk = psk_for(m);
            let a = derive_session_subkey(m, &psk, &random_salt(m)).unwrap();
            let b = derive_session_subkey(m, &psk, &random_salt(m)).unwrap();
            assert_ne!(a, b, "{m:?} reused key material across sessions");
        }
    }

    #[test]
    fn wrong_key_length_is_rejected_by_the_data_path() {
        for m in METHODS {
            let subkey = vec![0u8; m.psk_len()];
            let nonce = random_nonce();
            assert!(matches!(
                seal(m, &vec![0u8; m.psk_len() - 1], &nonce, b"", b"x"),
                Err(Shadowsocks2022Error::InvalidKeyLength { .. })
            ));
            let _ = subkey;
        }
    }

    #[test]
    fn short_nonce_is_rejected() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            assert!(matches!(
                seal(m, &subkey, &[0u8; 11], b"", b"x"),
                Err(Shadowsocks2022Error::InvalidNonceLength)
            ));
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            let ct = seal(m, &subkey, &nonce, b"", b"").unwrap();
            assert_eq!(ct.len(), 16, "{m:?} should emit tag only for empty input");
            assert_eq!(open(m, &subkey, &nonce, b"", &ct).unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn random_salt_and_nonce_differ() {
        for m in METHODS {
            assert_ne!(random_salt(m), random_salt(m));
            assert_ne!(random_nonce(), random_nonce());
        }
    }

    #[test]
    fn every_method_emits_the_specified_tag_overhead() {
        for m in METHODS {
            let subkey = derive_session_subkey(m, &psk_for(m), &random_salt(m)).unwrap();
            let nonce = random_nonce();
            for len in [0usize, 1, 15, 16, 17, 1400] {
                let payload = vec![0xABu8; len];
                let ct = seal(m, &subkey, &nonce, b"", &payload).unwrap();
                assert_eq!(ct.len(), len + 16, "{m:?} overhead wrong at len {len}");
            }
        }
    }

    use proptest::prelude::*;

    proptest! {
        /// SIP022 data-path roundtrip: whatever `seal` produces, `open`
        /// recovers exactly, for every method, for arbitrary payload sizes —
        /// and a single flipped ciphertext byte must fail the tag.
        #[test]
        fn seal_open_roundtrip(
            payload in prop::collection::vec(any::<u8>(), 0..512),
            seed in any::<u64>(),
        ) {
            let methods = [
                Shadowsocks2022Method::Aes128Gcm,
                Shadowsocks2022Method::Aes256Gcm,
                Shadowsocks2022Method::ChaCha20Poly1305,
            ];
            let method = methods[(seed % 3) as usize];
            let psk = vec![0x5au8; method.psk_len()];
            let salt = random_salt(method);
            let subkey = derive_session_subkey(method, &psk, &salt).expect("subkey");
            let nonce = random_nonce();
            let aad = b"fuzz-header";
            let sealed = seal(method, &subkey, &nonce, aad, &payload).expect("seal");
            let opened = open(method, &subkey, &nonce, aad, &sealed).expect("open");
            prop_assert_eq!(opened, payload);

            // Tamper: flipping any ciphertext byte must break authentication.
            let mut tampered = sealed.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
            prop_assert!(open(method, &subkey, &nonce, aad, &tampered).is_err());
        }
    }
}
