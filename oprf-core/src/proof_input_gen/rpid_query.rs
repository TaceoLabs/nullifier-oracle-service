use std::array;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use uuid::Uuid;

use crate::{oprf::OPrfClient, proof_input_gen::query::QueryProofInput};

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;

#[derive(Debug, Clone)]
pub struct RpIdQueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub pk: [[BaseField; 2]; super::query::MAX_PUBLIC_KEYS],
    pub pk_index: BaseField, // 0..6
    pub s: ScalarField,
    pub r: [BaseField; 2],
    // Merkle proof
    pub merkle_root: BaseField,
    pub mt_index: BaseField,
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    pub beta: ScalarField,
    pub nonce: BaseField,
    // Outputs
    pub q: [BaseField; 2],
}

impl<const MAX_DEPTH: usize> RpIdQueryProofInput<MAX_DEPTH> {
    pub const MAX_PUBLIC_KEYS: usize = QueryProofInput::<MAX_DEPTH>::MAX_PUBLIC_KEYS;

    pub fn generate_from_seed(seed: &[u8; 32]) -> (Self, BaseField) {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    // Also returns the query, since this is used in the RP-specific proof input generation
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> (Self, BaseField) {
        // Random inputs
        let request_id = Uuid::new_v4();
        let sk = EdDSAPrivateKey::random(rng);
        let mt_index_u64 = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
        let mt_index = BaseField::from(mt_index_u64);
        let siblings: [BaseField; MAX_DEPTH] = array::from_fn(|_| BaseField::rand(rng));
        let pk_index_u64 = rng.gen_range(0..Self::MAX_PUBLIC_KEYS) as u64;
        let pk_index = BaseField::from(pk_index_u64);
        let nonce = BaseField::rand(rng);

        // Calculate public keys
        let pk = sk.public();
        let mut pks = [[BaseField::zero(); 2]; super::query::MAX_PUBLIC_KEYS];
        for (i, pki) in pks.iter_mut().enumerate() {
            if i as u64 == pk_index_u64 {
                pki[0] = pk.pk.x;
                pki[1] = pk.pk.y;
            } else {
                let sk_i = ScalarField::rand(rng);
                let pk_i = (ark_babyjubjub::EdwardsAffine::generator() * sk_i).into_affine();
                pki[0] = pk_i.x;
                pki[1] = pk_i.y;
            }
        }

        // Calculate OPRF
        let oprf_client = OPrfClient::new(pk.pk);
        let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, mt_index, rng);

        // Sign the query
        let signature = sk.sign(blinding_factor.query);
        // Compute the Merkle root
        let merkkle_root =
            QueryProofInput::<MAX_DEPTH>::merkle_root_from_pks(&pks, &siblings, mt_index_u64);

        let result = Self {
            pk: pks,
            pk_index,
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            merkle_root: merkkle_root,
            mt_index,
            siblings,
            beta: blinding_factor.factor,
            nonce,
            q: [
                blinded_request.blinded_query.x,
                blinded_request.blinded_query.y,
            ],
        };

        (result, blinding_factor.query)
    }

    pub fn print(&self) {
        println!("pk: [");
        for (i, pk) in self.pk.iter().enumerate() {
            if i < self.pk.len() - 1 {
                println!("  [{:?}n, {:?}n],", pk[0], pk[1]);
            } else {
                println!("  [{:?}n, {:?}n]", pk[0], pk[1]);
            }
        }
        println!("],");
        println!("pk_index: {}n,", self.pk_index);
        println!("s: {}n,", self.s);
        println!("r: [{}n, {}n],", self.r[0], self.r[1]);
        println!("merkle_root: {}n,", self.merkle_root);
        println!("mt_index: {}n,", self.mt_index);
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
        println!("nonce: {}n,", self.nonce);
        println!("q: [{}n, {}n],", self.q[0], self.q[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpid_query_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = RpIdQueryProofInput::<10>::generate_from_seed(&seed).0;
        input1.print();
    }
}
