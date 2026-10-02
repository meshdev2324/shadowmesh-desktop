use crate::CommonError;
use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Authenticated Encryption with Associated Data (AEAD) wrapper using ChaCha20-Poly1305.
///
/// This utility is used for sensitive at-rest data like the Sovereignty Vault and
/// secure session persistence.
#[derive(Debug)]
pub struct VaultCipher {
    key: LessSafeKey,
}

impl VaultCipher {
    /// Attempts to create a new `VaultCipher` from a 32-byte key.
    ///
    /// # Arguments
    /// * `key_bytes` - A 32-byte secret key.
    ///
    /// # Errors
    /// Returns `CommonError::CryptoError` if the key is invalid for the algorithm.
    pub fn try_new(key_bytes: &[u8; 32]) -> Result<Self, CommonError> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)
            .map_err(|_| CommonError::CryptoError("Invalid key for ChaCha20-Poly1305".into()))?;
        Ok(Self { key: LessSafeKey::new(unbound_key) })
    }

    /// Encrypts the provided plaintext and returns the (nonce + ciphertext + tag) as a Vec<u8>.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CommonError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CommonError::CryptoError(e.to_string()))?;

        let mut result = Vec::with_capacity(NONCE_LEN + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypts the provided ciphertext (nonce + encrypted_data + tag).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CommonError> {
        if data.len() < NONCE_LEN {
            return Err(CommonError::CryptoError("Invalid ciphertext length".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes
                .try_into()
                .map_err(|_| CommonError::CryptoError("Invalid nonce size".into()))?,
        );

        let mut in_out = ciphertext.to_vec();
        let decrypted_slice = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CommonError::CryptoError(e.to_string()))?;

        Ok(decrypted_slice.to_vec())
    }
}

/// Securely zeroizes a key buffer on drop.
#[derive(Zeroize)]
pub struct SecureKey([u8; 32]);

impl SecureKey {
    /// Creates a new `SecureKey` from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_cipher_roundtrip() {
        let key = [0u8; 32];
        let cipher = VaultCipher::try_new(&key).expect("Failed to create cipher");
        let plaintext = b"shadowmesh-emergency-node-list";

        let encrypted = cipher.encrypt(plaintext).expect("Encryption failed");
        assert_ne!(plaintext.to_vec(), encrypted);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = cipher.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_vault_cipher_wrong_key() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let cipher1 = VaultCipher::try_new(&key1).expect("Failed to create cipher 1");
        let cipher2 = VaultCipher::try_new(&key2).expect("Failed to create cipher 2");

        let plaintext = b"secret";
        let encrypted = cipher1.encrypt(plaintext).unwrap();

        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
