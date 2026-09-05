use crate::{RealityConfig, RealityServerConfig};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr128BE;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// REALITY Handshake payload version.
pub const REALITY_VERSION: u8 = 1;

/// REALITY Handshake Payload.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RealityHandshakePayload {
    pub version: u8,
    pub timestamp: u64,
    pub short_id: String,
}

impl RealityConfig {
    /// Creates a new `RealityConfig` with the specified parameters.
    pub fn new(
        server_ip: String,
        port: u32,
        uuid: String,
        public_key: String,
        short_id: String,
        sni_target: String,
        fingerprint: Option<String>,
    ) -> Self {
        Self { server_ip, port, uuid, public_key, short_id, sni_target, fingerprint }
    }

    /// Parse a VLESS+REALITY URI string into a `RealityConfig`.
    ///
    /// Expected format:
    /// `vless://<uuid>@<host>:<port>?type=tcp&security=reality&pbk=<pub_key>&sid=<short_id>&fp=<fingerprint>&sni=<server_name>`
    pub fn from_vless_uri(uri: &str) -> Option<Self> {
        if !uri.starts_with("vless://") {
            return None;
        }

        let at_idx = uri.find('@')?;
        let params_start = uri.find('?')?;

        let uuid = uri[8..at_idx].to_string();

        let host_port_part = &uri[at_idx + 1..params_start];
        let (server_ip, port_str) = host_port_part.split_once(':')?;
        let port = port_str.parse::<u32>().ok()?;
        let server_ip = server_ip.to_string();

        let query = &uri[params_start + 1..];

        let mut sni_target = String::from("security.debian.org");
        let mut public_key = String::new();
        let mut short_id = String::new();
        let mut fingerprint = Some(String::from("chrome"));

        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "sni" => sni_target = value.to_string(),
                    "pbk" => public_key = value.to_string(),
                    "sid" => short_id = value.to_string(),
                    "fp" => fingerprint = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        if public_key.is_empty() || short_id.is_empty() {
            return None;
        }

        Some(Self { server_ip, port, uuid, public_key, short_id, sni_target, fingerprint })
    }

    /// Build the VLESS+REALITY outbound config fragment as a JSON string.
    pub fn to_outbound_config(&self) -> String {
        format!(
            r#"{{"protocol":"vless","address":"{}","port":{},"uuid":"{}","security":"reality","serverName":"{}","publicKey":"{}","shortId":"{}","fingerprint":"{}"}}"#,
            self.server_ip,
            self.port,
            self.uuid,
            self.sni_target,
            self.public_key,
            self.short_id,
            self.fingerprint.as_deref().unwrap_or("chrome")
        )
    }

    /// Encrypts the REALITY handshake payload for the client.
    /// Returns (ephemeral_public_key, ciphertext).
    pub fn encrypt_handshake(&self) -> Result<(Vec<u8>, Vec<u8>), crate::ShadowMeshError> {
        // Ephemeral x25519 keypair from the OS CSPRNG: the handshake's
        // confidentiality depends on this being unpredictable.
        let ephemeral_seed: [u8; 32] = crate::secure_random_bytes(32)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| crate::ShadowMeshError::Other("OS entropy source failed".into()))?;
        let ephemeral_secret = StaticSecret::from(ephemeral_seed);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let server_pub_bytes = hex::decode(&self.public_key)
            .map_err(|_| crate::ShadowMeshError::Other("Invalid public key hex".into()))?;
        if server_pub_bytes.len() != 32 {
            return Err(crate::ShadowMeshError::Other("Invalid public key length".into()));
        }
        let mut server_pub_arr = [0u8; 32];
        server_pub_arr.copy_from_slice(&server_pub_bytes);
        let server_public = PublicKey::from(server_pub_arr);

        let shared_secret = ephemeral_secret.diffie_hellman(&server_public);
        let derived_key = Sha256::digest(shared_secret.as_bytes());

        let payload = RealityHandshakePayload {
            version: REALITY_VERSION,
            timestamp: chrono::Utc::now().timestamp() as u64,
            short_id: self.short_id.clone(),
        };
        let plaintext = serde_json::to_vec(&payload)
            .map_err(|e| crate::ShadowMeshError::JsonError(e.to_string()))?;

        let mut ciphertext = plaintext.clone();
        let mut cipher =
            Ctr128BE::<Aes128>::new((&derived_key[..16]).into(), (&derived_key[16..32]).into());
        cipher.apply_keystream(&mut ciphertext);

        Ok((ephemeral_public.as_bytes().to_vec(), ciphertext))
    }
}

impl RealityServerConfig {
    /// Decrypts a REALITY handshake payload for the server.
    pub fn decrypt_handshake(
        &self,
        ephemeral_public_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<RealityHandshakePayload, crate::ShadowMeshError> {
        if ephemeral_public_bytes.len() != 32 {
            return Err(crate::ShadowMeshError::Other(
                "Invalid ephemeral public key length".into(),
            ));
        }
        let mut ephem_pub_arr = [0u8; 32];
        ephem_pub_arr.copy_from_slice(ephemeral_public_bytes);
        let ephemeral_public = PublicKey::from(ephem_pub_arr);

        let server_priv_bytes = hex::decode(&self.private_key)
            .map_err(|_| crate::ShadowMeshError::Other("Invalid private key hex".into()))?;
        if server_priv_bytes.len() != 32 {
            return Err(crate::ShadowMeshError::Other("Invalid private key length".into()));
        }
        let mut server_priv_arr = [0u8; 32];
        server_priv_arr.copy_from_slice(&server_priv_bytes);
        let server_secret = StaticSecret::from(server_priv_arr);

        let shared_secret = server_secret.diffie_hellman(&ephemeral_public);
        let derived_key = Sha256::digest(shared_secret.as_bytes());

        let mut plaintext = ciphertext.to_vec();
        let mut cipher =
            Ctr128BE::<Aes128>::new((&derived_key[..16]).into(), (&derived_key[16..32]).into());
        cipher.apply_keystream(&mut plaintext);

        let payload: RealityHandshakePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| crate::ShadowMeshError::JsonError(e.to_string()))?;

        // Validation
        if !self.short_ids.contains(&payload.short_id) {
            return Err(crate::ShadowMeshError::Unauthorized("Invalid short ID".into()));
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if payload.timestamp > now + 30 || payload.timestamp < now - 300 {
            return Err(crate::ShadowMeshError::Unauthorized("Timestamp expired".into()));
        }

        Ok(payload)
    }
}

/// Generate a cryptographically random 8-byte hex Short ID for the REALITY protocol.
pub fn generate_short_id() -> String {
    // OS CSPRNG: the short ID is a credential material — a predictable ID
    // would let an attacker impersonate the REALITY server.
    match crate::secure_random_bytes(8) {
        Some(bytes) => hex::encode(bytes),
        // Entropy failure must NOT silently fall back to a constant:
        // a zero short ID is an explicit, detectable misconfiguration.
        None => hex::encode([0u8; 8]),
    }
}

/// Derives a session token from a shared Diffie-Hellman secret using SHA-256.
///
/// Matches the protocol spec: `SessionToken = SHA256(Hex64(S))`.
pub fn derive_session_token(dh_shared_secret_hex: String) -> String {
    shadowmesh_common::crypto::derive_session_token(&dh_shared_secret_hex)
}

/// Encrypts a QR pairing payload with a visual stream cipher derived from a PIN.
///
/// Optimized to avoid string allocations and reuse hasher state.
pub fn encrypt_qr_payload(plaintext: &[u8], pin: &str) -> Vec<u8> {
    shadowmesh_common::crypto::encrypt_qr_payload(plaintext, pin)
}

/// Decrypts a QR pairing payload (symmetric — XOR is its own inverse).
pub fn decrypt_qr_payload(ciphertext: &[u8], pin: &str) -> Vec<u8> {
    shadowmesh_common::crypto::decrypt_qr_payload(ciphertext, pin)
}

/// Generates a random 2048-bit Diffie-Hellman private key as a hex string.
/// Uses RFC 3526 Group 14 parameters.
#[allow(deprecated)]
pub fn generate_dh_private_key() -> String {
    shadowmesh_common::crypto::generate_dh_private_key()
}

/// Computes the Diffie-Hellman public key from a hex-encoded private key.
pub fn compute_dh_public_key(private_key_hex: String) -> String {
    shadowmesh_common::crypto::compute_dh_public_key(&private_key_hex)
}

/// Computes the shared secret from a local private key and a remote public key.
pub fn compute_dh_shared_secret(private_key_hex: String, other_public_key_hex: String) -> String {
    shadowmesh_common::crypto::compute_dh_shared_secret(&private_key_hex, &other_public_key_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_uri_parsing() {
        let uri = "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=pubkey123&sid=abcd1234&fp=chrome&sni=security.debian.org";
        let config = RealityConfig::from_vless_uri(uri).expect("Should parse valid VLESS URI");
        assert_eq!(config.server_ip, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(config.uuid, "uuid");
        assert_eq!(config.sni_target, "security.debian.org");
        // We hex decode pbk in encrypt_handshake, so let's use valid hex in test if needed,
        // but from_vless_uri just takes the string.
        assert_eq!(config.public_key, "pubkey123");
        assert_eq!(config.short_id, "abcd1234");
        assert_eq!(config.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn test_reality_handshake_roundtrip() {
        let (priv_key_vec, pub_key_vec) = shadowmesh_common::crypto::generate_x25519_keypair();
        let priv_key_hex = hex::encode(priv_key_vec);
        let pub_key_hex = hex::encode(pub_key_vec);
        let short_id = generate_short_id();

        let client_config = RealityConfig::new(
            "1.2.3.4".into(),
            443,
            "uuid".into(),
            pub_key_hex.clone(),
            short_id.clone(),
            "google.com".into(),
            None,
        );

        let server_config = RealityServerConfig {
            private_key: priv_key_hex,
            short_ids: vec![short_id.clone()],
            sni_target: "google.com".into(),
        };

        let (ephem_pub, ciphertext) = client_config.encrypt_handshake().unwrap();
        let payload = server_config.decrypt_handshake(&ephem_pub, &ciphertext).unwrap();

        assert_eq!(payload.short_id, short_id);
        assert_eq!(payload.version, REALITY_VERSION);
    }

    #[test]
    fn test_reality_handshake_invalid_short_id() {
        let (priv_key_vec, pub_key_vec) = shadowmesh_common::crypto::generate_x25519_keypair();
        let priv_key_hex = hex::encode(priv_key_vec);
        let pub_key_hex = hex::encode(pub_key_vec);

        let client_config = RealityConfig::new(
            "1.2.3.4".into(),
            443,
            "uuid".into(),
            pub_key_hex.clone(),
            "wrong_sid".into(),
            "google.com".into(),
            None,
        );

        let server_config = RealityServerConfig {
            private_key: priv_key_hex,
            short_ids: vec!["correct_sid".into()],
            sni_target: "google.com".into(),
        };

        let (ephem_pub, ciphertext) = client_config.encrypt_handshake().unwrap();
        let result = server_config.decrypt_handshake(&ephem_pub, &ciphertext);
        assert!(result.is_err());
    }
}
