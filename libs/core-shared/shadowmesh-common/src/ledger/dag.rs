use super::merkle::MerkleTree;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Errors raised by the Merkle-DAG ledger primitives.
///
/// Every fallible operation in this module returns `LedgerResult` instead of
/// unwrapping. A ledger block feeds a settlement path (see
/// `shadowmesh_server::system::ledger`), where a panic is a strictly worse
/// outcome than a rejected block: it aborts the task that was processing the
/// block and takes down every other block that task was going to settle.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// A block or event could not be serialised into its canonical form.
    /// The chain link is derived from that serialisation, so the chain cannot
    /// be extended or verified without it.
    #[error("ledger serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type LedgerResult<T> = Result<T, LedgerError>;

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
    /// Builds a block, deriving its Merkle root over the canonical encoding of
    /// each event.
    ///
    /// Returns `Err` if an event cannot be serialised; the caller decides
    /// whether that means "reject the block" or "reject the whole append".
    pub fn new(parent_hash: Option<[u8; 32]>, events: Vec<SettlementEvent>) -> LedgerResult<Self> {
        let data: Vec<Vec<u8>> = events
            .iter()
            .map(|e| serde_json::to_vec(e).map_err(LedgerError::from))
            .collect::<Result<_, _>>()?;

        let tree = MerkleTree::new(&data);
        let merkle_root = tree.root.unwrap_or([0u8; 32]);

        Ok(Self { parent_hash, events, merkle_root, timestamp: Utc::now().timestamp() })
    }

    /// SHA-256 over the block's canonical serialisation.
    ///
    /// This is the value the *next* block carries as its `parent_hash`, so the
    /// link is only as trustworthy as this serialisation step. Propagates
    /// rather than unwrapping (TECH_DEBT RC-001).
    pub fn chain_hash(&self) -> LedgerResult<[u8; 32]> {
        let data = serde_json::to_vec(self)?;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hasher.finalize());
        Ok(h)
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

    /// Appends a block, linking it to the current chain head.
    ///
    /// The chain is left untouched when the parent link cannot be computed, so
    /// a failure never leaves a partially-extended ledger behind.
    pub fn append_block(&mut self, events: Vec<SettlementEvent>) -> LedgerResult<()> {
        let parent = match self.chain.last() {
            Some(b) => Some(b.chain_hash()?),
            None => None,
        };

        self.chain.push(LedgerBlock::new(parent, events)?);
        Ok(())
    }

    /// Checks that each block points at the hash of its predecessor.
    ///
    /// `Ok(true)` means the chain is intact. `Ok(false)` means it is not — a
    /// real integrity violation. `Err` means the check could not be performed
    /// at all, which callers must not confuse with the former.
    pub fn verify_integrity(&self) -> LedgerResult<bool> {
        // Basic check: each block must point to the previous one
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];

            if current.parent_hash != Some(previous.chain_hash()?) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_append_and_verify() {
        let mut ledger = MeshLedger::new();

        ledger
            .append_block(vec![SettlementEvent::Mint {
                code_hash: "code1".into(),
                amount: 1000,
                ts: Utc::now().timestamp(),
            }])
            .unwrap();

        ledger
            .append_block(vec![SettlementEvent::Spend {
                device_hash: "dev1".into(),
                amount: 10,
                ts: Utc::now().timestamp(),
            }])
            .unwrap();

        assert_eq!(ledger.chain.len(), 2);
        assert!(ledger.verify_integrity().unwrap());
    }

    /// M15 / TECH_DEBT RC-001: the integrity check reports a verdict as
    /// `Ok(bool)`. It never panics, and it never reports a violation as an
    /// error — a caller must be able to tell "chain is broken" from
    /// "chain could not be checked".
    #[test]
    fn test_verify_integrity_reports_verdict_not_error() {
        let mut ledger = MeshLedger::new();
        ledger.append_block(vec![]).unwrap();
        // A single block has no predecessor to link to, and an empty chain has
        // nothing to check. Both are intact, not "unchecked".
        assert!(ledger.verify_integrity().unwrap());
        assert!(MeshLedger::new().verify_integrity().unwrap());

        ledger.append_block(vec![]).unwrap();
        assert!(ledger.verify_integrity().unwrap());

        // Tamper with the link on the head block. The chain is now broken, and
        // the verdict is a definite `Ok(false)` — not an `Err`, which would mean
        // the check could not be performed at all.
        ledger.chain[1].parent_hash = Some([0xAA; 32]);
        assert!(!ledger.verify_integrity().unwrap());
    }

    /// The parent link is the SHA-256 of the predecessor's canonical
    /// serialisation, so `chain_hash` is the single definition of it for both
    /// `append_block` and `verify_integrity`. This pins that the two agree.
    #[test]
    fn test_chain_hash_is_the_parent_link() {
        let mut ledger = MeshLedger::new();
        ledger
            .append_block(vec![SettlementEvent::NodeAnchor {
                node_id: "node-1".into(),
                public_key: "pk-1".into(),
                ts: 1_700_000_000,
            }])
            .unwrap();
        let genesis_hash = ledger.chain[0].chain_hash().unwrap();

        ledger
            .append_block(vec![SettlementEvent::NodeAnchor {
                node_id: "node-2".into(),
                public_key: "pk-2".into(),
                ts: 1_700_000_001,
            }])
            .unwrap();

        assert_eq!(ledger.chain[1].parent_hash, Some(genesis_hash));
        assert!(ledger.verify_integrity().unwrap());
    }

    /// A genesis block has no parent; an empty block gets the all-zero Merkle
    /// root rather than panicking on `tree.root` (which is `None` for zero
    /// leaves).
    #[test]
    fn test_genesis_and_empty_block() {
        let genesis = LedgerBlock::new(None, vec![]).unwrap();
        assert_eq!(genesis.parent_hash, None);
        assert_eq!(genesis.merkle_root, [0u8; 32]);

        let ledger = MeshLedger { chain: vec![genesis] };
        assert!(ledger.verify_integrity().unwrap());
    }
}
