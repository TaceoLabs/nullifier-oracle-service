use std::str::FromStr;

use ark_ec::{AdditiveGroup, AffineRepr as _};
use oprf_types::MerkleRoot;
use poseidon2::Poseidon2;
use rand::Rng;

use crate::services::merkle_registry::PublicKey;

/// A generic Merkle tree over u128 leaves.
pub struct MerkleTree {
    /// Each level is a vector of hashes. Level 0 = leaves, last = root.
    levels: Vec<Vec<ark_babyjubjub::Fq>>,
    poseidon2_2: Poseidon2<ark_babyjubjub::Fq, 2, 5>,
    poseidon2_16: Poseidon2<ark_babyjubjub::Fq, 16, 5>,
    domain_separator: ark_babyjubjub::Fq,
}

impl MerkleTree {
    /// Create a new empty tree with the given hasher.
    pub fn empty() -> Self {
        MerkleTree {
            levels: Vec::new(),
            poseidon2_2: Poseidon2::default(),
            poseidon2_16: Poseidon2::default(),
            domain_separator: ark_babyjubjub::Fq::from_str("105702839725298824521994315")
                .expect("works"),
        }
    }

    /// Create a new MerkleTree from a list of leaves.
    pub fn random<R: Rng>(amount: usize, r: &mut R) -> Self {
        let mut tree = MerkleTree::empty();
        if amount == 0 {
            return tree;
        }

        // Compute leaf hashes
        let leaf_hashes = (0..amount)
            .map(|_| tree.merkle_leaf(PublicKey::random(r)))
            .collect::<Vec<_>>();

        // Build levels
        let mut levels = vec![leaf_hashes.clone()];
        let mut current = leaf_hashes;

        while current.len() > 1 {
            let mut next_level = Vec::with_capacity(current.len().div_ceil(2));
            for i in (0..current.len()).step_by(2) {
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    current[i] // duplicate last if odd
                };
                next_level.push(tree.hash_children(left, right));
            }
            levels.push(next_level.clone());
            current = next_level;
        }

        tree.levels = levels;
        tree
    }

    fn merkle_leaf(&self, pk: PublicKey) -> ark_babyjubjub::Fq {
        let mut input = [ark_babyjubjub::Fq::ZERO; 16];
        input[0] = self.domain_separator;
        for i in 0..7 {
            input[i * 2 + 1] = pk.elements[i].x().expect("not infinity");
            input[i * 2 + 2] = pk.elements[i].y().expect("not infinity");
        }
        self.poseidon2_16.permutation(&input)[1]
    }

    fn hash_children(
        &self,
        left: ark_babyjubjub::Fq,
        right: ark_babyjubjub::Fq,
    ) -> ark_babyjubjub::Fq {
        self.poseidon2_2.permutation(&[left, right])[0] + left
    }

    /// Current root hash. Returns `None` if no leaves yet.
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot::from(
            self.levels
                .last()
                .and_then(|lvl| lvl.first().cloned())
                .expect("tree is empty"),
        )
    }

    pub fn push_leaf(&mut self, leaf: PublicKey) {
        let leaf_hash = self.merkle_leaf(leaf);

        if self.levels.is_empty() {
            // First leaf: just create level 0.
            self.levels.push(vec![leaf_hash]);
            return;
        } else {
            self.levels[0].push(leaf_hash);
        }

        // Index of the newly inserted leaf at level 0.
        let mut idx = self.levels[0].len() - 1;
        let mut level = 0;

        loop {
            // If this is the top level (no parent level yet) and it has >1 nodes, ensure next level exists.
            if self.levels.len() == level + 1 {
                // We are about to (maybe) create a parent level.
                self.levels.push(Vec::new());
            }

            let parent_idx = idx / 2;
            let left_child_index = parent_idx * 2;

            let left = self.levels[level][left_child_index];
            let right = if left_child_index + 1 < self.levels[level].len() {
                self.levels[level][left_child_index + 1]
            } else {
                // Placeholder duplication for incomplete pair.
                left
            };

            let parent_hash = self.hash_children(left, right);

            // Ensure parent level capacity
            let parent_level = level + 1;
            if self.levels[parent_level].len() == parent_idx {
                // New parent appended
                self.levels[parent_level].push(parent_hash);
            } else {
                // Existing parent: check if it changes
                if self.levels[parent_level][parent_idx] == parent_hash {
                    // No change; if the parent already existed and did not change,
                    // ancestors above cannot change (because their inputs are unchanged).
                    // Early exit optimization.
                    break;
                } else {
                    // Update parent hash and continue upward
                    self.levels[parent_level][parent_idx] = parent_hash;
                }
            }

            // If new parent level now has exactly one element, it's the root; stop.
            if self.levels[parent_level].len() == 1 {
                break;
            }

            // Move up
            idx = parent_idx;
            level = parent_level;
        }
    }

    #[expect(dead_code)]
    /// Return the proof (sibling hashes) for a leaf index.
    pub fn get_proof(&self, index: usize) -> Vec<ark_babyjubjub::Fq> {
        let mut idx = index;
        let mut proof = Vec::new();

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx % 2 == 0 {
                if idx + 1 < level.len() {
                    level[idx + 1]
                } else {
                    level[idx]
                }
            } else {
                level[idx - 1]
            };
            proof.push(sibling);
            idx /= 2;
        }
        proof
    }
}
