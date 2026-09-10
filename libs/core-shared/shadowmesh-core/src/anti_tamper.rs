use crate::ShadowMeshError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Configuration for the anti-tamper subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiTamperConfig {
    /// A map of component names to their expected SHA256 hexadecimal hashes.
    pub expected_hashes: HashMap<String, String>, // key: component name, value: SHA256 hash
}

/// A checker responsible for verifying the integrity of system components and application signatures.
pub struct AntiTamperChecker {
    config: AntiTamperConfig,
}

impl AntiTamperChecker {
    /// Creates a new `AntiTamperChecker` with the provided configuration.
    pub fn new(config: AntiTamperConfig) -> Self {
        Self { config }
    }

    /// Verifies the integrity of a specific component by comparing its SHA256 hash
    /// against the expected value in the configuration.
    ///
    /// Returns `Ok(true)` if the hash matches or if no hash is configured for the component.
    /// Returns `Ok(false)` if there is a mismatch.
    pub fn verify_component(
        &self,
        component_name: String,
        component_data: Vec<u8>,
    ) -> Result<bool, ShadowMeshError> {
        let expected_hash = match self.config.expected_hashes.get(&component_name) {
            Some(hash) => hash,
            None => return Ok(true), // no expected hash → skip check (future extension)
        };

        let actual_hash = {
            let mut hasher = Sha256::new();
            hasher.update(component_data);
            let hash = hasher.finalize();
            hex::encode(hash)
        };

        // 🛡️ Defense-in-Depth: Use constant-time comparison for integrity hashes
        Ok(self.constant_time_compare(expected_hash, &actual_hash))
    }

    /// Verifies the application signature hash against the expected value for the package.
    ///
    /// This is typically used on Android to ensure the APK hasn't been resigned.
    pub fn verify_app_signature(
        &self,
        package_name: String,
        signature_hash: String,
    ) -> Result<bool, ShadowMeshError> {
        // In a real senior-level production app, the expected hash would be
        // obfuscated or derived at compile-time.
        let expected_signature = match self.config.expected_hashes.get(&package_name) {
            Some(hash) => hash,
            None => return Ok(true), // Skip if no hash configured (e.g. Debug)
        };

        Ok(self.constant_time_compare(expected_signature, &signature_hash))
    }

    /// Internal helper for constant-time string comparison to prevent timing side-channels.
    fn constant_time_compare(&self, a: &str, b: &str) -> bool {
        use subtle::ConstantTimeEq;
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        if a_bytes.len() != b_bytes.len() {
            return false;
        }
        // Big-Tech Standard: Industrial-grade side-channel resistance via 'subtle' crate
        a_bytes.ct_eq(b_bytes).into()
    }

    /// Checks a collection of components for any signs of tampering.
    ///
    /// Returns `Ok(true)` if at least one component fails verification.
    pub fn is_tampered(
        &self,
        components: HashMap<String, Vec<u8>>,
    ) -> Result<bool, ShadowMeshError> {
        for (name, data) in components {
            if !self.verify_component(name, data)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_verify_component_success() -> Result<(), ShadowMeshError> {
        let test_data = b"test component data";
        let expected_hash = hex::encode(sha2::Sha256::digest(test_data));
        let mut expected_hashes = HashMap::new();
        expected_hashes.insert("test_component".to_string(), expected_hash);
        let config = AntiTamperConfig { expected_hashes };
        let checker = AntiTamperChecker::new(config);

        let result = checker.verify_component("test_component".to_string(), test_data.to_vec());
        assert!(result.is_ok());
        assert!(result?);
        Ok(())
    }

    #[test]
    fn test_verify_component_failure() -> Result<(), ShadowMeshError> {
        let test_data = b"test component data";
        let wrong_data = b"tampered data";
        let expected_hash = hex::encode(sha2::Sha256::digest(test_data));
        let mut expected_hashes = HashMap::new();
        expected_hashes.insert("test_component".to_string(), expected_hash);
        let config = AntiTamperConfig { expected_hashes };
        let checker = AntiTamperChecker::new(config);

        let result = checker.verify_component("test_component".to_string(), wrong_data.to_vec());
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_component_skip_unknown() -> Result<(), ShadowMeshError> {
        let config = AntiTamperConfig { expected_hashes: HashMap::new() };
        let checker = AntiTamperChecker::new(config);

        let result =
            checker.verify_component("unknown_component".to_string(), b"any data".to_vec());
        assert!(result.is_ok());
        assert!(result?); // should skip unknown components and return true
        Ok(())
    }

    #[test]
    fn test_is_tampered_false() -> Result<(), ShadowMeshError> {
        let test_data1 = b"data1";
        let test_data2 = b"data2";
        let mut expected_hashes = HashMap::new();
        expected_hashes.insert("comp1".to_string(), hex::encode(sha2::Sha256::digest(test_data1)));
        expected_hashes.insert("comp2".to_string(), hex::encode(sha2::Sha256::digest(test_data2)));
        let config = AntiTamperConfig { expected_hashes };
        let checker = AntiTamperChecker::new(config);

        let mut components = HashMap::new();
        components.insert("comp1".to_string(), test_data1.to_vec());
        components.insert("comp2".to_string(), test_data2.to_vec());

        let result = checker.is_tampered(components);
        assert!(result.is_ok());
        assert!(!result?); // not tampered
        Ok(())
    }

    #[test]
    fn test_is_tampered_true() -> Result<(), ShadowMeshError> {
        let test_data1 = b"data1";
        let tampered_data = b"tampered";
        let mut expected_hashes = HashMap::new();
        expected_hashes.insert("comp1".to_string(), hex::encode(sha2::Sha256::digest(test_data1)));
        let config = AntiTamperConfig { expected_hashes };
        let checker = AntiTamperChecker::new(config);

        let mut components = HashMap::new();
        components.insert("comp1".to_string(), tampered_data.to_vec());

        let result = checker.is_tampered(components);
        assert!(result.is_ok());
        assert!(result?); // tampered
        Ok(())
    }
}
