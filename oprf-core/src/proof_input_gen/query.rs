use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPrivateKey;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use std::array;
use uuid::Uuid;

use crate::oprf::OPrfClient;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;

pub const MAX_PUBLIC_KEYS: usize = 7;

#[derive(Debug, Clone)]
pub struct QueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub pk: [[BaseField; 2]; MAX_PUBLIC_KEYS],
    pub pk_index: BaseField, // 0..6
    pub s: ScalarField,
    pub r: [BaseField; 2],
    // Merkle proof
    pub merkle_root: BaseField,
    pub mt_index: BaseField,
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    pub beta: ScalarField,
    pub rp_id: BaseField,
    pub action: BaseField,
    pub nonce: BaseField,
    // Outputs
    pub q: [BaseField; 2],
}

impl<const MAX_DEPTH: usize> QueryProofInput<MAX_DEPTH> {
    pub const MAX_PUBLIC_KEYS: usize = MAX_PUBLIC_KEYS;
    const PK_DS: &[u8] = b"World ID PK";

    // Returns the domain separator for the hashing of all public keys as a field element
    fn get_pk_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::PK_DS)
    }

    // Also returns the query, since this is used in the nullifier proof input generation
    pub fn generate_from_seed(seed: &[u8; 32]) -> (Self, BaseField) {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    // Also returns the query, since this is used in the nullifier proof input generation
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> (Self, BaseField) {
        // Random inputs
        let request_id = Uuid::new_v4();
        let sk = EdDSAPrivateKey::random(rng);
        let mt_index_u64 = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
        let mt_index = BaseField::from(mt_index_u64);
        let rp_id = BaseField::rand(rng);
        let action = BaseField::rand(rng);
        let siblings: [BaseField; MAX_DEPTH] = array::from_fn(|_| BaseField::rand(rng));
        let pk_index_u64 = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
        let pk_index = BaseField::from(pk_index_u64);
        let nonce = BaseField::rand(rng);

        // Calculate public keys
        let pk = sk.public();
        let mut pks = [[BaseField::zero(); 2]; MAX_PUBLIC_KEYS];
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
        let query = OPrfClient::generate_query(mt_index, rp_id, action);
        let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, query, rng);

        // Sign the query
        let signature = sk.sign(blinding_factor.query);
        // Compute the Merkle root
        let merkkle_root = Self::merkle_root_from_pks(&pks, &siblings, mt_index_u64);

        let result = Self {
            pk: pks,
            pk_index,
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            merkle_root: merkkle_root,
            mt_index,
            siblings,
            beta: blinding_factor.factor,
            rp_id,
            action,
            nonce,
            q: [
                blinded_request.blinded_query.x,
                blinded_request.blinded_query.y,
            ],
        };

        (result, blinding_factor.query)
    }

    // Also returns the query, since this is used in the nullifier proof input generation
    #[expect(clippy::too_many_arguments)]
    pub fn new<R: Rng + CryptoRng>(
        request_id: Uuid,
        sk: EdDSAPrivateKey,
        pks: [[BaseField; 2]; MAX_PUBLIC_KEYS],
        pk_index: u64,
        merkle_root: BaseField,
        mt_index: u64,
        siblings: [BaseField; MAX_DEPTH],
        rp_id: BaseField,
        action: BaseField,
        nonce: BaseField,
        rng: &mut R,
    ) -> (Self, BaseField) {
        let pk = sk.public();
        let pk_index_ = BaseField::from(pk_index);
        let mt_index_ = BaseField::from(mt_index);

        // Calculate OPRF
        let oprf_client = OPrfClient::new(pk.pk);
        let query = OPrfClient::generate_query(mt_index_, rp_id, action);
        let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, query, rng);

        // Sign the query
        let signature = sk.sign(blinding_factor.query);

        let result = Self {
            pk: pks,
            pk_index: pk_index_,
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            merkle_root,
            mt_index: mt_index_,
            siblings,
            beta: blinding_factor.factor,
            rp_id,
            action,
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
        println!("rp_id: {}n,", self.rp_id);
        println!("action: {}n,", self.action);
        println!("nonce: {}n,", self.nonce);
        println!("q: [{}n, {}n],", self.q[0], self.q[1]);
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "pk": self.pk.iter().map(|pk| [pk[0].to_string(), pk[1].to_string()]).collect::<Vec<_>>(),
            "pk_index": self.pk_index.to_string(),
            "s": self.s.to_string(),
            "r": [self.r[0].to_string(), self.r[1].to_string()],
            "merkle_root": self.merkle_root.to_string(),
            "mt_index": self.mt_index.to_string(),
            "siblings": self.siblings.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "beta": self.beta.to_string(),
            "rp_id": self.rp_id.to_string(),
            "action": self.action.to_string(),
            "nonce": self.nonce.to_string()
        })
    }

    pub fn merkle_root_from_pks(
        pks: &[[BaseField; 2]; MAX_PUBLIC_KEYS],
        siblings: &[BaseField; MAX_DEPTH],
        index: u64,
    ) -> BaseField {
        // Hash pk
        let poseidon2_16 = Poseidon2::<_, 16, 5>::default();
        let mut input = array::from_fn(|_| BaseField::zero());
        input[0] = Self::get_pk_ds();
        for (i, pk) in pks.iter().enumerate() {
            input[1 + i * 2] = pk[0];
            input[1 + i * 2 + 1] = pk[1];
        }
        let leaf = poseidon2_16.permutation(&input)[1];
        Self::merkle_root(leaf, siblings, index)
    }

    pub(super) fn merkle_root(
        leaf: BaseField,
        siblings: &[BaseField; MAX_DEPTH],
        mut index: u64,
    ) -> BaseField {
        let mut current_hash = leaf;

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
