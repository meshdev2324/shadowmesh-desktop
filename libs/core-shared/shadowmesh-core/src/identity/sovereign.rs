use crate::ShadowMeshError;
use base64::prelude::*;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents an attestation report from a hardware enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Manufacturer identifier (e.g., "intel_sgx", "aws_nitro").
    pub provider: String,
    /// Hardware-signed quote or document.
    pub quote: String,
    /// The public key generated inside the enclave.
    pub public_key: String,
    /// Nonce used for freshness verification.
    pub nonce: String,
    /// Hash of the enclave binary.
    pub measurement: String,
}

/// Interface for interacting with Hardware Trusted Execution Environments.
pub trait EnclaveProvider: Send + Sync {
    /// Returns the provider name.
    fn name(&self) -> &str;

    /// Generates a hardware-bound keypair and returns the public part.
    fn generate_identity_key(&self) -> Result<String, ShadowMeshError>;

    /// Produces a remote attestation report for the node.
    fn produce_attestation(&self, nonce: &str) -> Result<AttestationReport, ShadowMeshError>;

    /// Signs a challenge within the secure enclave.
    fn sign_challenge(&self, challenge: &[u8]) -> Result<String, ShadowMeshError>;
}

/// A sovereign identity for a VPN node, isolating keys from the host.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SovereignIdentity {
    /// The public part of the hardware-isolated identity key.
    #[zeroize(skip)]
    pub public_key: String,
    // Note: In production, the private key would never be held in this struct in cleartext.
    // It would be managed by the EnclaveProvider.
    private_key: Option<String>,
}

impl SovereignIdentity {
    /// Creates a new identity by initializing the enclave.
    pub fn new(provider: Arc<dyn EnclaveProvider>) -> Result<Self, ShadowMeshError> {
        let public_key = provider.generate_identity_key()?;
        Ok(Self {
            public_key,
            private_key: None, // Key is managed by the enclave
        })
    }

    /// Returns the fingerprint of the public key.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key.as_bytes());
        BASE64_STANDARD.encode(hasher.finalize())
    }
}

/// Mock Enclave Provider for non-TEE environments and CI.
pub struct MockEnclaveProvider {
    secret: Mutex<Option<StaticSecret>>,
}

impl Default for MockEnclaveProvider {
    fn default() -> Self {
        Self { secret: Mutex::new(None) }
    }
}

use std::sync::{Arc, Mutex};

impl EnclaveProvider for MockEnclaveProvider {
    fn name(&self) -> &str {
        "mock_enclave"
    }

    fn generate_identity_key(&self) -> Result<String, ShadowMeshError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let pub_b64 = BASE64_STANDARD.encode(public.as_bytes());

        let mut guard =
            self.secret.lock().map_err(|_| ShadowMeshError::Other("Lock poisoned".into()))?;
        *guard = Some(secret);

        Ok(pub_b64)
    }

    fn produce_attestation(&self, nonce: &str) -> Result<AttestationReport, ShadowMeshError> {
        let guard =
            self.secret.lock().map_err(|_| ShadowMeshError::Other("Lock poisoned".into()))?;
        let pk = guard
            .as_ref()
            .map(|s| BASE64_STANDARD.encode(PublicKey::from(s).as_bytes()))
            .ok_or(ShadowMeshError::Other("Key not generated".into()))?;

        Ok(AttestationReport {
            provider: "mock_enclave".into(),
            quote: "MOCKED_HARDWARE_QUOTE".into(),
            public_key: pk,
            nonce: nonce.to_string(),
            measurement: "MOCKED_BINARY_HASH".into(),
        })
    }

    fn sign_challenge(&self, challenge: &[u8]) -> Result<String, ShadowMeshError> {
        // In a real enclave, this would be an Ed25519 signature.
        // For mock, we just HMAC-SHA256 it with the secret key's bytes.
        let guard =
            self.secret.lock().map_err(|_| ShadowMeshError::Other("Lock poisoned".into()))?;
        let s = guard.as_ref().ok_or(ShadowMeshError::Other("Key not generated".into()))?;

        let mut hasher = Sha256::new();
        hasher.update(s.to_bytes());
        hasher.update(challenge);
        Ok(BASE64_STANDARD.encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sovereign_identity_creation() {
        let provider = Arc::new(MockEnclaveProvider::default());
        let identity = SovereignIdentity::new(provider).unwrap();

        assert!(!identity.public_key.is_empty());
        assert!(identity.private_key.is_none());
    }

    #[test]
    fn test_identity_fingerprint() {
        let provider = Arc::new(MockEnclaveProvider::default());
        let identity = SovereignIdentity::new(provider).unwrap();
        let fp = identity.fingerprint();

        assert_eq!(fp.len(), 44); // Base64 of SHA256
    }

    #[test]
    fn test_attestation_flow() {
        let provider = Arc::new(MockEnclaveProvider::default());
        provider.generate_identity_key().unwrap();

        let report = provider.produce_attestation("nonce123").unwrap();
        assert_eq!(report.provider, "mock_enclave");
        assert_eq!(report.nonce, "nonce123");
        assert!(!report.public_key.is_empty());
    }

    #[test]
    fn test_signing_flow() {
        let provider = Arc::new(MockEnclaveProvider::default());
        provider.generate_identity_key().unwrap();

        let challenge = b"test_challenge";
        let sig = provider.sign_challenge(challenge).unwrap();
        assert!(!sig.is_empty());

        // Verify deterministic signing in mock
        let sig2 = provider.sign_challenge(challenge).unwrap();
        assert_eq!(sig, sig2);
    }
}
