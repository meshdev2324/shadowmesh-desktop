use super::merkle::MerkleTree;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// A settlement event recorded on the mesh ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettlementEvent {
    /// Initial minting of sovereignty credits.
    Mint { code_hash: String, amount: u64, ts: i64 },
    /// Consumption of credits by a terminal.
    Spend { device_hash: String, amount: u64, ts: i64 },
    /// A hardware-verified node joining the mesh.
    NodeAnchor { node_id: String, public_key: String, ts: i64 },
    /// Shard-to-Shard Capacity Trade (RFC-006).
    /// Shard A pays Shard B for carrying traffic.
    FabricTrade {
        from_shard: String,
        to_shard: String,
        amount_fc: u64,
        proof_hash: [u8; 32],
        ts: i64,
    },
}

/// A block in the Merkle-DAG ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub parent_hash: Option<[u8; 32]>,
    pub events: Vec<SettlementEvent>,
    pub merkle_root: [u8; 32],
    pub timestamp: i64,
}

impl LedgerBlock {
    pub fn new(parent_hash: Option<[u8; 32]>, events: Vec<SettlementEvent>) -> Self {
        let data: Vec<Vec<u8>> = events.iter().map(|e| serde_json::to_vec(e).unwrap()).collect();

        let tree = MerkleTree::new(&data);
        let merkle_root = tree.root.unwrap_or([0u8; 32]);

        Self { parent_hash, events, merkle_root, timestamp: Utc::now().timestamp() }
    }
}

/// A local view of the Distributed Mesh Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshLedger {
    pub chain: Vec<LedgerBlock>,
}

impl Default for MeshLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshLedger {
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    pub fn append_block(&mut self, events: Vec<SettlementEvent>) {
        let parent = self.chain.last().map(|b| {
            // Compute hash of the entire block as the parent link
            let data = serde_json::to_vec(b).unwrap();
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            let mut h = [0u8; 32];
            h.copy_from_slice(&hasher.finalize());
            h
        });

        self.chain.push(LedgerBlock::new(parent, events));
    }

    pub fn verify_integrity(&self) -> bool {
        // Basic check: each block must point to the previous one
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];

            let data = serde_json::to_vec(previous).unwrap();
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            if current.parent_hash != Some(hasher.finalize().into()) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_append_and_verify() {
        let mut ledger = MeshLedger::new();

        ledger.append_block(vec![SettlementEvent::Mint {
            code_hash: "code1".into(),
            amount: 1000,
            ts: Utc::now().timestamp(),
        }]);

        ledger.append_block(vec![SettlementEvent::Spend {
            device_hash: "dev1".into(),
            amount: 10,
            ts: Utc::now().timestamp(),
        }]);

        assert_eq!(ledger.chain.len(), 2);
        assert!(ledger.verify_integrity());
    }
}
