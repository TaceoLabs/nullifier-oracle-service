use std::str::FromStr;

use ark_ec::{AdditiveGroup, AffineRepr as _};
use oprf_types::MerkleRoot;
use poseidon2::Poseidon2;

use crate::services::pk_registry::PublicKey;

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

    /// Add a new leaf, recomputing all parent hashes.
    pub fn push_leaf(&mut self, leaf: PublicKey) {
        let leaf_hash = self.merkle_leaf(leaf);

        if self.levels.is_empty() {
            self.levels.push(vec![leaf_hash]);
        } else {
            self.levels[0].push(leaf_hash);
        }
        self.recompute();
    }

    fn recompute(&mut self) {
        let mut current = self.levels[0].clone();
        let mut new_levels = vec![current.clone()];

        while current.len() > 1 {
            let mut next_level = Vec::with_capacity(current.len().div_ceil(2));
            for i in (0..current.len()).step_by(2) {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    &current[i] // duplicate last if odd
                };
                next_level.push(self.hash_children(*left, *right));
            }
            current = next_level.clone();
            new_levels.push(next_level);
        }
        self.levels = new_levels;
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
