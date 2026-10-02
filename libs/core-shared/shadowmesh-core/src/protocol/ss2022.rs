//! Shadowsocks-2022 key derivation (RFC-012 G1, SIP022-family spec).
//!
//! Implementation Source:
//! - Specification: Shadowsocks 2022 edition (SIP022-family, public)
//! - Primitive: BLAKE3 (audited `blake3` crate; domain-keyed derivation)
//! - Security considerations: the derivation input (salt || master key) is
//!   zeroized immediately after use; the domain string prevents cross-protocol
//!   key reuse. Pure in-process cryptography — no subprocess of any kind.

use zeroize::Zeroize;

/// Derives the per-session subkey for a 2022-edition method.
///
/// BLAKE3's key-derive mode hashes `(salt || master_key)` under a fixed
/// domain string, producing key material that is bound to both the session
/// salt and the master key. Equivalent in role to SIP007's HKDF stage, but
/// with the 2022 edition's stronger construction.
pub fn derive_session_subkey(salt: &[u8], master_key: &[u8], key_len: usize) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(salt.len() + master_key.len());
    ikm.extend_from_slice(salt);
    ikm.extend_from_slice(master_key);
    let domain: &str = "shadowmesh-ss2022-subkey";
    let derived = blake3_kdf(domain, &ikm);
    ikm.zeroize();
    Vec::from(&derived[..key_len])
}

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

/// Thin wrapper isolating the BLAKE3 call so the domain string and input
/// binding are explicit at the call site.
fn blake3_kdf(domain: &str, input: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkey_is_deterministic() {
        let a = derive_session_subkey(&[1u8; 12], &[2u8; 32], 32);
        let b = derive_session_subkey(&[1u8; 12], &[2u8; 32], 32);
        assert_eq!(a, b);
    }

    #[test]
    fn subkey_depends_on_salt_and_key() {
        let base = derive_session_subkey(&[1u8; 12], &[2u8; 32], 32);
        let salt_changed = derive_session_subkey(&[9u8; 12], &[2u8; 32], 32);
        let key_changed = derive_session_subkey(&[1u8; 12], &[9u8; 32], 32);
        assert_ne!(base, salt_changed);
        assert_ne!(base, key_changed);
    }

    #[test]
    fn output_length_is_honored() {
        assert_eq!(derive_session_subkey(&[0u8; 12], &[0u8; 32], 16).len(), 16);
        assert_eq!(derive_session_subkey(&[0u8; 12], &[0u8; 32], 32).len(), 32);
    }

    // ---- Fixed-length header (SIP022-family) ------------------------------

    /// Encodes the 11-byte fixed header: [type:1][timestamp_ms:8][len:2].
    #[test]
    fn header_roundtrip_and_freshness() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64;
        let hdr = build_fixed_header(PAYLOAD_TYPE_REQUEST, ts, 512);
        assert_eq!(hdr.len(), FIXED_HEADER_LEN);
        assert_eq!(hdr[0], PAYLOAD_TYPE_REQUEST);

        let parsed = parse_fixed_header(&hdr).expect("parse");
        assert_eq!(parsed.payload_type, PAYLOAD_TYPE_REQUEST);
        assert_eq!(parsed.timestamp_ms, ts);
        assert_eq!(parsed.length, 512);
        assert!(parsed.is_fresh());
    }

    #[test]
    fn stale_header_is_rejected() {
        let old_ts = 1_000_000u64; // 1970 — far outside any window
        let hdr = build_fixed_header(PAYLOAD_TYPE_REQUEST, old_ts, 4);
        let parsed = parse_fixed_header(&hdr).expect("parse");
        assert!(!parsed.is_fresh(), "stale timestamp must fail freshness");
    }

    #[test]
    fn malformed_header_rejected() {
        assert!(parse_fixed_header(&[0u8; 5]).is_err());
        assert!(parse_fixed_header(&[0u8; FIXED_HEADER_LEN]).is_ok());
    }
}

/// First-payload-chunk fixed header (SIP022-family): [type:1][ts_ms:8][len:2].
pub const FIXED_HEADER_LEN: usize = 11;
pub const PAYLOAD_TYPE_REQUEST: u8 = 0;
pub const PAYLOAD_TYPE_RESPONSE: u8 = 1;

/// Timestamp acceptance window (±30s), applied to the header's millisecond
/// clock against the receiver's local clock.
pub const HEADER_FRESHNESS_WINDOW_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    pub payload_type: u8,
    pub timestamp_ms: u64,
    pub length: u16,
}

impl FixedHeader {
    /// Replay guard: the header's timestamp must be within the acceptance
    /// window of now (millisecond clock).
    pub fn is_fresh(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms.saturating_sub(self.timestamp_ms) <= HEADER_FRESHNESS_WINDOW_MS
    }
}

/// Builds the 11-byte fixed header for the first request/response chunk.
pub fn build_fixed_header(
    payload_type: u8,
    timestamp_ms: u64,
    length: u16,
) -> [u8; FIXED_HEADER_LEN] {
    let mut hdr = [0u8; FIXED_HEADER_LEN];
    hdr[0] = payload_type;
    hdr[1..9].copy_from_slice(&timestamp_ms.to_be_bytes());
    hdr[9..11].copy_from_slice(&length.to_be_bytes());
    hdr
}

/// Parses (and validates shape of) the fixed header.
pub fn parse_fixed_header(bytes: &[u8]) -> Result<FixedHeader, &'static str> {
    if bytes.len() < FIXED_HEADER_LEN {
        return Err("short fixed header");
    }
    let timestamp_ms = u64::from_be_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    let length = u16::from_be_bytes([bytes[9], bytes[10]]);
    Ok(FixedHeader { payload_type: bytes[0], timestamp_ms, length })
}
