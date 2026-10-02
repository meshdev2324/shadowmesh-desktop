use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node in the Merkle Tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleNode {
    pub hash: [u8; 32],
}

impl MerkleNode {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        Self { hash }
    }

    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(left.hash);
        hasher.update(right.hash);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        Self { hash }
    }
}

/// A cryptographic proof of inclusion in a Merkle Tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// A lightweight Merkle Tree for decentralized credit settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<MerkleNode>,
    pub root: Option<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(data_blocks: &[Vec<u8>]) -> Self {
        let leaves = data_blocks.iter().map(|d| MerkleNode::new(d)).collect();
        let mut tree = Self { leaves, root: None };
        tree.recalculate_root();
        tree
    }

    pub fn recalculate_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }

        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(MerkleNode::combine(&chunk[0], &chunk[1]));
                } else {
                    // Odd number of nodes: Duplicate the last one (Standard Merkle practice)
                    next_level.push(MerkleNode::combine(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
        }

        self.root = Some(current_level[0].hash);
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut idx = leaf_index;

        while current_level.len() > 1 {
            if idx.is_multiple_of(2) {
                // If it's a left node, sibling is to the right
                if idx + 1 < current_level.len() {
                    siblings.push(current_level[idx + 1].hash);
                } else {
                    // Sibling is itself if odd at end
                    siblings.push(current_level[idx].hash);
                }
            } else {
                // If it's a right node, sibling is to the left
                siblings.push(current_level[idx - 1].hash);
            }

            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(MerkleNode::combine(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(MerkleNode::combine(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(MerkleProof { leaf_index, siblings })
    }

    pub fn verify_proof(root: [u8; 32], leaf: &[u8], proof: &MerkleProof) -> bool {
        let mut current_hash = MerkleNode::new(leaf).hash;
        let mut idx = proof.leaf_index;

        for sibling in &proof.siblings {
            let mut hasher = Sha256::new();
            if idx.is_multiple_of(2) {
                hasher.update(current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current_hash);
            }
            current_hash.copy_from_slice(&hasher.finalize());
            idx /= 2;
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_determinism() {
        let data = vec![b"tx1".to_vec(), b"tx2".to_vec(), b"tx3".to_vec()];
        let tree1 = MerkleTree::new(&data);
        let tree2 = MerkleTree::new(&data);
        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_merkle_inclusion_proof() {
        let data = vec![b"tx1".to_vec(), b"tx2".to_vec(), b"tx3".to_vec(), b"tx4".to_vec()];
        let tree = MerkleTree::new(&data);
        let root = tree.root.unwrap();

        let proof = tree.generate_proof(2).unwrap(); // Proof for tx3
        assert!(MerkleTree::verify_proof(root, b"tx3", &proof));
        assert!(!MerkleTree::verify_proof(root, b"tx1", &proof));
    }

    #[test]
    fn test_odd_leaves_handling() {
        let data = vec![b"tx1".to_vec(), b"tx2".to_vec(), b"tx3".to_vec()];
        let tree = MerkleTree::new(&data);
        let root = tree.root.unwrap();

        let proof = tree.generate_proof(2).unwrap();
        assert!(MerkleTree::verify_proof(root, b"tx3", &proof));
    }
}
