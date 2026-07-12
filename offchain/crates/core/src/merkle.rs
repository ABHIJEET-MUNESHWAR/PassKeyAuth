//! Keccak-256 Merkle tree, proofs, and verification — the off-chain mirror of
//! the on-chain `merkle` module in `programs/passkeyauth`.
//!
//! The issuer's eligible-set tree is built here; proofs generated here verify
//! on-chain (and vice-versa) because both sides hash identically:
//! `parent = keccak256(left ++ right)`.

use sha3::{Digest as _, Keccak256};

/// Hash an ordered pair of 32-byte nodes into their parent (keccak-256).
#[must_use]
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut node = [0u8; 32];
    node.copy_from_slice(&out);
    node
}

/// Recompute a root from a leaf and its proof (mirror of the on-chain check).
#[must_use]
pub fn compute_root(leaf: [u8; 32], siblings: &[[u8; 32]], index_bits: u64) -> [u8; 32] {
    let mut node = leaf;
    for (level, sib) in siblings.iter().enumerate() {
        let go_right = (index_bits >> level) & 1 == 1;
        node = if go_right {
            hash_pair(sib, &node)
        } else {
            hash_pair(&node, sib)
        };
    }
    node
}

/// Verify a leaf's membership under `root`.
#[must_use]
pub fn verify(leaf: [u8; 32], siblings: &[[u8; 32]], index_bits: u64, root: [u8; 32]) -> bool {
    compute_root(leaf, siblings, index_bits) == root
}

/// A complete keccak Merkle tree over a set of leaves.
///
/// Odd levels duplicate the final node (a common, verification-compatible
/// convention). `levels[0]` are the leaves; the last level is the single root.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a tree from leaves. An empty input yields a zero root.
    #[must_use]
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![[0u8; 32]]],
            };
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() {
                    cur[i + 1]
                } else {
                    cur[i]
                };
                next.push(hash_pair(&left, &right));
                i += 2;
            }
            levels.push(next);
        }
        Self { levels }
    }

    /// The Merkle root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        *self.levels.last().unwrap().last().unwrap()
    }

    /// Number of leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// A membership proof `(siblings, index_bits)` for the leaf at `index`.
    #[must_use]
    pub fn proof(&self, index: usize) -> Option<(Vec<[u8; 32]>, u64)> {
        if index >= self.leaf_count() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut index_bits = 0u64;
        let mut idx = index;
        for (level, nodes) in self.levels.iter().enumerate() {
            if nodes.len() <= 1 {
                break;
            }
            let is_right = idx % 2 == 1;
            let sib_idx = if is_right {
                idx - 1
            } else {
                (idx + 1).min(nodes.len() - 1)
            };
            siblings.push(nodes[sib_idx]);
            if is_right {
                index_bits |= 1 << level;
            }
            idx /= 2;
        }
        Some((siblings, index_bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let t = MerkleTree::from_leaves(vec![leaf(1)]);
        assert_eq!(t.root(), leaf(1));
        let (sib, bits) = t.proof(0).unwrap();
        assert!(verify(leaf(1), &sib, bits, t.root()));
    }

    #[test]
    fn two_leaf_proofs_verify() {
        let t = MerkleTree::from_leaves(vec![leaf(0xAA), leaf(0xBB)]);
        assert_eq!(t.root(), hash_pair(&leaf(0xAA), &leaf(0xBB)));
        for i in 0..2 {
            let (sib, bits) = t.proof(i).unwrap();
            assert!(verify(t.levels[0][i], &sib, bits, t.root()));
        }
    }

    #[test]
    fn four_leaf_proofs_verify() {
        let leaves: Vec<_> = (1..=4).map(leaf).collect();
        let t = MerkleTree::from_leaves(leaves.clone());
        for (i, l) in leaves.iter().enumerate() {
            let (sib, bits) = t.proof(i).unwrap();
            assert!(verify(*l, &sib, bits, t.root()));
        }
    }

    #[test]
    fn odd_leaf_count_verifies() {
        let leaves: Vec<_> = (1..=5).map(leaf).collect();
        let t = MerkleTree::from_leaves(leaves.clone());
        for (i, l) in leaves.iter().enumerate() {
            let (sib, bits) = t.proof(i).unwrap();
            assert!(verify(*l, &sib, bits, t.root()), "leaf {i} failed");
        }
        assert!(t.proof(5).is_none());
    }

    #[test]
    fn wrong_leaf_fails() {
        let t = MerkleTree::from_leaves(vec![leaf(1), leaf(2), leaf(3), leaf(4)]);
        let (sib, bits) = t.proof(0).unwrap();
        assert!(!verify(leaf(9), &sib, bits, t.root()));
    }

    #[test]
    fn empty_tree_zero_root() {
        let t = MerkleTree::from_leaves(vec![]);
        assert_eq!(t.root(), [0u8; 32]);
    }
}
