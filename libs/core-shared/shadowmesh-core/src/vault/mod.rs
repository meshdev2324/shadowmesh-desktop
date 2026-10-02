use crate::ShadowMeshError;
use crate::VPNNode;
use shadowmesh_common::crypto::vault_cipher::VaultCipher;
use std::fs;
use std::path::PathBuf;

/// Persistent, encrypted storage for emergency node lists and sensitive session metadata.
///
/// The vault ensures that the client can still function and failover to backup nodes
/// even if the primary API is blocked.
#[derive(Debug)]
pub struct SovereigntyVault {
    storage_path: PathBuf,
    cipher: VaultCipher,
}

impl SovereigntyVault {
    /// Attempts to create a new `SovereigntyVault` with the provided storage path and master key.
    pub fn try_new(storage_path: PathBuf, master_key: &[u8; 32]) -> Result<Self, ShadowMeshError> {
        Ok(Self {
            storage_path,
            cipher: VaultCipher::try_new(master_key)
                .map_err(|e| ShadowMeshError::Common(e.to_string()))?,
        })
    }

    /// Stores a list of emergency nodes securely in the vault.
    pub fn store_emergency_nodes(&self, nodes: &[VPNNode]) -> Result<(), ShadowMeshError> {
        let json =
            serde_json::to_vec(nodes).map_err(|e| ShadowMeshError::JsonError(e.to_string()))?;
        let encrypted =
            self.cipher.encrypt(&json).map_err(|e| ShadowMeshError::Common(e.to_string()))?;

        // Atomic write via temp file
        let temp_path = self.storage_path.with_extension("tmp");
        fs::write(&temp_path, encrypted).map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        fs::rename(temp_path, &self.storage_path)
            .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Loads the list of emergency nodes from the vault.
    pub fn load_emergency_nodes(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        if !self.storage_path.exists() {
            return Ok(vec![]);
        }

        let encrypted =
            fs::read(&self.storage_path).map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let decrypted =
            self.cipher.decrypt(&encrypted).map_err(|e| ShadowMeshError::Common(e.to_string()))?;

        let nodes: Vec<VPNNode> = serde_json::from_slice(&decrypted)
            .map_err(|e| ShadowMeshError::JsonError(e.to_string()))?;

        Ok(nodes)
    }

    /// Deletes all data in the vault.
    pub fn purge(&self) -> Result<(), ShadowMeshError> {
        if self.storage_path.exists() {
            fs::remove_file(&self.storage_path)
                .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_persistence_roundtrip() -> Result<(), ShadowMeshError> {
        let dir = tempdir().map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let path = dir.path().join("sovereignty.vault");
        let key = [0u8; 32];
        let vault = SovereigntyVault::try_new(path, &key)
            .map_err(|e| ShadowMeshError::Other(e.to_string()))?;

        let nodes = vec![VPNNode {
            id: "emergency-1".into(),
            name: "Emergency Node".into(),
            region: "global".into(),
            country: "XX".into(),
            endpoint: "1.1.1.1:443".into(),
            public_key: "pubkey".into(),
            load: 0,
            latency: 0,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        }];

        vault.store_emergency_nodes(&nodes)?;
        let loaded = vault.load_emergency_nodes()?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "emergency-1");
        Ok(())
    }
}
