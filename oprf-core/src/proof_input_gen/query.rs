use ark_ff::{UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPrivateKey;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use std::array;

use crate::oprf::OPrfClient;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;

#[derive(Debug, Clone)]
pub struct QueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub pk: [BaseField; 2],
    pub s: ScalarField,
    pub r: [BaseField; 2],
    // Merkle proof
    pub merkle_root: BaseField,
    pub index: BaseField,
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    pub beta: ScalarField,
    pub rp_id: BaseField,
    pub action: BaseField,
    // Outputs
    pub q: [BaseField; 2],
}

impl<const MAX_DEPTH: usize> QueryProofInput<MAX_DEPTH> {
    // Also returns the query, since this is used in the nullifier proof input generation
    pub fn generate_from_seed(seed: &[u8; 32]) -> (Self, BaseField) {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    // Also returns the query, since this is used in the nullifier proof input generation
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> (Self, BaseField) {
        // Random inputs
        let sk = EdDSAPrivateKey::random(rng);
        let index_u64 = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
        let index = BaseField::from(index_u64);
        let rp_id = BaseField::rand(rng);
        let action = BaseField::rand(rng);
        let siblings: [BaseField; MAX_DEPTH] = array::from_fn(|_| BaseField::rand(rng));

        // Calculate OPRF
        let pk = sk.public();
        let oprf_client = OPrfClient::new(pk.pk);
        let query = OPrfClient::generate_query(index, rp_id, action);
        let (blinded_request, blinding_factor) = oprf_client.blind_query(query, rng);

        // Sign the query
        let signature = sk.sign(blinding_factor.query);
        // Compute the Merkle root
        let merkkle_root = Self::merkle_root(pk.pk.x, pk.pk.y, &siblings, index_u64);

        let result = Self {
            pk: [pk.pk.x, pk.pk.y],
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            merkle_root: merkkle_root,
            index,
            siblings,
            beta: blinding_factor.factor,
            rp_id,
            action,
            q: [
                blinded_request.blinded_query.x,
                blinded_request.blinded_query.y,
            ],
        };

        (result, blinding_factor.query)
    }

    pub fn print(&self) {
        println!("pk: [{}n, {}n],", self.pk[0], self.pk[1]);
        println!("s: {}n,", self.s);
        println!("r: [{}n, {}n],", self.r[0], self.r[1]);
        println!("merkle_root: {}n,", self.merkle_root);
        println!("index: {}n,", self.index);
        println!("siblings: [");
        for (i, s) in self.siblings.iter().enumerate() {
            if i < self.siblings.len() - 1 {
                println!("  {}n,", s);
            } else {
                println!("  {}n", s);
            }
        }
        println!("],");
        println!("beta: {}n,", self.beta);
        println!("rp_id: {}n,", self.rp_id);
        println!("action: {}n,", self.action);
        println!("q: [{}n, {}n],", self.q[0], self.q[1]);
    }

    pub fn merkle_root(
        pk_x: BaseField,
        pk_y: BaseField,
        siblings: &[BaseField; MAX_DEPTH],
        mut index: u64,
    ) -> BaseField {
        // Hash pk
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let mut current_hash = poseidon2_3.permutation(&[BaseField::zero(), pk_x, pk_y])[1];

        // Merkle chain
        let poseidon2_2 = Poseidon2::<_, 2, 5>::default();
        for s in siblings {
            if index & 1 == 0 {
                current_hash = poseidon2_2.permutation(&[current_hash, *s])[0] + current_hash;
            } else {
                current_hash = poseidon2_2.permutation(&[*s, current_hash])[0] + s;
            }
            index >>= 1;
        }

        current_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = QueryProofInput::<10>::generate_from_seed(&seed).0;
        input1.print();
    }
}
