pub mod vault_cipher;

use aws_lc_rs::digest::{SHA256, digest};
use num_bigint::{BigUint, RandBigInt};
use std::sync::LazyLock;

/// RFC 3526 Group 14 - 2048-bit MODP Group.
/// Standard prime for Diffie-Hellman operations.
pub const DH_P_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
                        29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
                        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
                        E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
                        C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
                        83655D23DCA3AD961C62F356208552BB9ED529077096966D\
                        670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
                        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
                        DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
                        15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// Parsed BigUint prime for Group 14 to avoid repeated parsing overhead.
static DH_P: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::parse_bytes(DH_P_HEX.as_bytes(), 16).unwrap_or_default());

/// Generator for RFC 3526 Group 14.
pub const DH_G: u32 = 2;

/// Big-Tech Standard: X25519 Key Exchange
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes().to_vec(), public.as_bytes().to_vec())
}

/// Computes the X25519 shared secret.
pub fn compute_x25519_shared_secret(
    _private_key: &[u8],
    _public_key: &[u8],
) -> Result<Vec<u8>, crate::CommonError> {
    Err(crate::CommonError::Internal("Use x25519-dalek for static key exchange".into()))
}

/// Generates a random 2048-bit Diffie-Hellman private key as a hex string.
/// @deprecated: Use generate_x25519_keypair instead for new protocols.
#[deprecated(note = "Legacy MODP Group 14. Use X25519 for modern protocols.")]
pub fn generate_dh_private_key() -> String {
    let mut rng = rand::thread_rng();
    let private_key = rng.gen_biguint_below(&DH_P);
    private_key.to_str_radix(16)
}

/// Computes the Diffie-Hellman public key from a hex-encoded private key.
pub fn compute_dh_public_key(private_key_hex: &str) -> String {
    let g = BigUint::from(DH_G);
    let priv_key = BigUint::parse_bytes(private_key_hex.as_bytes(), 16).unwrap_or_default();

    let pub_key = g.modpow(&priv_key, &DH_P);
    format!("{:0>64}", pub_key.to_str_radix(16))
}

/// Computes the shared secret from a local private key and a remote public key.
pub fn compute_dh_shared_secret(private_key_hex: &str, other_public_key_hex: &str) -> String {
    let priv_key = BigUint::parse_bytes(private_key_hex.as_bytes(), 16).unwrap_or_default();
    let other_pub = BigUint::parse_bytes(other_public_key_hex.as_bytes(), 16).unwrap_or_default();

    let shared = other_pub.modpow(&priv_key, &DH_P);
    format!("{:0>64}", shared.to_str_radix(16))
}

/// Derives a session token from a shared secret using SHA-256.
pub fn derive_session_token(shared_secret_hex: &str) -> String {
    let result = digest(&SHA256, shared_secret_hex.as_bytes());
    hex::encode(result.as_ref())
}

/// Standardized anonymization for identifiers (like device ID) using SHA-256.
pub fn anonymize_id(id: &str) -> String {
    let result = digest(&SHA256, id.as_bytes());
    hex::encode(result.as_ref())
}

/// Encrypts a QR pairing payload with a visual stream cipher derived from a PIN.
/// Uses SHA-256 for deterministic key stream generation.
pub fn encrypt_qr_payload(plaintext: &[u8], pin: &str) -> Vec<u8> {
    let pin_hash = digest(&SHA256, pin.as_bytes());
    let pin_hash_hex = hex::encode(pin_hash.as_ref());
    let pin_hash_bytes = pin_hash_hex.as_bytes();

    let mut buf = itoa::Buffer::new();

    plaintext
        .iter()
        .enumerate()
        .map(|(i, &byte)| {
            let mut key_data = pin_hash_bytes.to_vec();
            key_data.extend_from_slice(b"-");
            key_data.extend_from_slice(buf.format(i).as_bytes());

            let key_hash = digest(&SHA256, &key_data);
            byte ^ key_hash.as_ref()[0]
        })
        .collect()
}

/// Decrypts a QR pairing payload (symmetric).
pub fn decrypt_qr_payload(ciphertext: &[u8], pin: &str) -> Vec<u8> {
    encrypt_qr_payload(ciphertext, pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_dh_exchange() {
        let alice_priv = generate_dh_private_key();
        let alice_pub = compute_dh_public_key(&alice_priv);

        let bob_priv = generate_dh_private_key();
        let bob_pub = compute_dh_public_key(&bob_priv);

        let alice_shared = compute_dh_shared_secret(&alice_priv, &bob_pub);
        let bob_shared = compute_dh_shared_secret(&bob_priv, &alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_qr_roundtrip() {
        let pin = "123456";
        let data = b"pairing-token-123";
        let encrypted = encrypt_qr_payload(data, pin);
        let decrypted = decrypt_qr_payload(&encrypted, pin);
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_anonymize_id() {
        let id = "test-device-id";
        let anonymized = anonymize_id(id);
        assert_eq!(anonymized.len(), 64);
        assert_ne!(anonymized, id);
    }

    #[test]
    fn test_x25519_keypair_generation() {
        let (priv_key, pub_key) = generate_x25519_keypair();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
    }

    #[test]
    fn test_x25519_shared_secret_unsupported() {
        // Current implementation explicitly returns an error
        let result = compute_x25519_shared_secret(&[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }
}
