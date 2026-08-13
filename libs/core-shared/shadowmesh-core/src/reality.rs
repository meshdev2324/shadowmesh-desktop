use crate::RealityConfig;
use rand::Rng;

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

        let mut sni_target = String::from("google.com");
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
}

/// Generate a cryptographically random 8-byte hex Short ID for the REALITY protocol.
pub fn generate_short_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.r#gen();
    hex::encode(bytes)
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
        let uri = "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=pubkey123&sid=abcd1234&fp=chrome&sni=google.com";
        let config = RealityConfig::from_vless_uri(uri).expect("Should parse valid VLESS URI");
        assert_eq!(config.server_ip, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(config.uuid, "uuid");
        assert_eq!(config.sni_target, "google.com");
        assert_eq!(config.public_key, "pubkey123");
        assert_eq!(config.short_id, "abcd1234");
        assert_eq!(config.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn test_invalid_uri_returns_none() {
        assert!(RealityConfig::from_vless_uri("wireguard://...").is_none());
    }

    #[test]
    fn test_qr_payload_encrypt_decrypt_roundtrip() {
        let pin = "123456";
        let plaintext = b"session_token_payload";
        let ciphertext = encrypt_qr_payload(plaintext, pin);
        assert_ne!(ciphertext, plaintext, "Ciphertext must differ from plaintext");
        let decrypted = decrypt_qr_payload(&ciphertext, pin);
        assert_eq!(decrypted, plaintext, "Decrypted payload must match original");
    }

    #[test]
    fn test_derive_session_token_is_deterministic() {
        let secret_hex = "deadbeef0102030405060708090a0b0c0d0e0f";
        let token_a = derive_session_token(secret_hex.to_string());
        let token_b = derive_session_token(secret_hex.to_string());
        assert_eq!(token_a, token_b);
        assert_eq!(token_a.len(), 64, "SHA-256 hex string must be 64 chars");
    }
}
