//! Pure, host-testable Merkle set-membership verification (keccak-256).
//!
//! An issuer publishes a Merkle root over the commitments of eligible
//! identities. A user proves their commitment is a leaf of that tree — thereby
//! proving eligibility for the issuer's schema **without revealing which leaf**
//! — and burns a nullifier so the proof cannot be replayed. This is the
//! hash-based, CU-bounded core of the zero-knowledge attestation flow.
use solana_keccak_hasher::hashv;

/// Hash an ordered pair of 32-byte nodes into their parent.
#[inline]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hashv(&[left, right]).0
}

/// Recompute the Merkle root from `leaf` and its `proof`.
///
/// `index_bits` encodes each level's direction (bit set → the current node is
/// the RIGHT child, i.e. the sibling is on the left). Bounded by `proof.len()`.
#[must_use]
pub fn compute_root(leaf: [u8; 32], proof: &[[u8; 32]], index_bits: u64) -> [u8; 32] {
    let mut node = leaf;
    for (level, sibling) in proof.iter().enumerate() {
        let go_right = (index_bits >> level) & 1 == 1;
        node = if go_right {
            hash_pair(sibling, &node)
        } else {
            hash_pair(&node, sibling)
        };
    }
    node
}

/// Verify that `leaf` is a member of the tree with the given `root`.
#[must_use]
pub fn verify(leaf: [u8; 32], proof: &[[u8; 32]], index_bits: u64, root: [u8; 32]) -> bool {
    compute_root(leaf, proof, index_bits) == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn single_leaf_tree_root_is_leaf() {
        let l = leaf(1);
        assert!(verify(l, &[], 0, l));
    }

    #[test]
    fn two_leaf_tree_membership() {
        let a = leaf(0xAA);
        let b = leaf(0xBB);
        let root = hash_pair(&a, &b);
        // `a` is the left child (bit 0 unset); sibling is `b`.
        assert!(verify(a, &[b], 0, root));
        // `b` is the right child (bit 0 set); sibling is `a`.
        assert!(verify(b, &[a], 1, root));
    }

    #[test]
    fn four_leaf_tree_membership() {
        let (a, b, c, d) = (leaf(1), leaf(2), leaf(3), leaf(4));
        let ab = hash_pair(&a, &b);
        let cd = hash_pair(&c, &d);
        let root = hash_pair(&ab, &cd);
        // `c` path: level0 sibling d (c is left → bit0=0), level1 sibling ab (cd is right → bit1=1).
        assert!(verify(c, &[d, ab], 0b10, root));
        // `b` path: level0 sibling a (b is right → bit0=1), level1 sibling cd (ab is left → bit1=0).
        assert!(verify(b, &[a, cd], 0b01, root));
    }

    #[test]
    fn wrong_proof_fails() {
        let a = leaf(0xAA);
        let b = leaf(0xBB);
        let root = hash_pair(&a, &b);
        assert!(!verify(a, &[leaf(0xCC)], 0, root));
        assert!(!verify(a, &[b], 1, root)); // wrong direction
    }
}
