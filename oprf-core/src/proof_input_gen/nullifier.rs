use ark_ec::CurveGroup;
use ark_ff::{UniformRand, Zero};
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};

use crate::{
    oprf::{BlindedOPrfRequest, BlindingFactor, OPrfClient, OPrfKey, OPrfService},
    proof_input_gen::query::QueryProofInput,
};

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[derive(Debug, Clone)]
pub struct NullifierProofInput<const MAX_DEPTH: usize> {
    // Signature
    pub nonce: BaseField,
    pub user_pk: [BaseField; 2],
    pub query_s: ScalarField,
    pub query_r: [BaseField; 2],
    // Merkle proof
    pub merkle_root: BaseField,
    pub index: BaseField,
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    pub beta: ScalarField,
    // Dlog Equality Proof
    pub dlog_e: BaseField,
    pub dlog_s: ScalarField,
    pub oprf_pk: [BaseField; 2],
    pub oprf_response_blinded: [BaseField; 2],
    // Unblinded response
    pub oprf_response: [BaseField; 2],
    // Nullifier computation
    pub nullified_action: BaseField,
    pub nullified_epoch: BaseField,
    // Outputs
    pub nullifier: BaseField,
}

impl<const MAX_DEPTH: usize> NullifierProofInput<MAX_DEPTH> {
    pub fn generate_from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha12Rng::from_seed(*seed);
        Self::generate(&mut rng)
    }

    pub fn nullifier(
        nullified_action: BaseField,
        nullified_epoch: BaseField,
        oprf_response: BaseField,
        index: BaseField,
    ) -> BaseField {
        let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
        let mut state = poseidon2_4.permutation(&[
            BaseField::zero(),
            oprf_response,
            nullified_action,
            nullified_epoch,
        ]);
        state[1] += index;
        poseidon2_4.permutation(&state)[1]
    }

    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        //  Random inputs
        let sk = OPrfKey::new(ScalarField::rand(rng));
        let action = BaseField::rand(rng);
        let epoch = BaseField::rand(rng);

        // Create the query proof
        let query_proof_input = QueryProofInput::<MAX_DEPTH>::generate(rng);

        // These come from the QueryProof, but need to be reconstructed
        let blinded_query = Affine::new_unchecked(query_proof_input.q[0], query_proof_input.q[1]);
        let blinded_oprf_query = BlindedOPrfRequest {
            request_id: uuid::Uuid::new_v4(),
            blinded_query,
        };
        let blinding_factor = BlindingFactor {
            factor: query_proof_input.beta,
            query: query_proof_input.index,
            request_id: blinded_oprf_query.request_id,
        };
        let blinding_factor_prepared = blinding_factor.prepare();

        let oprf_service = OPrfService::new(sk);
        let (oprf_blinded_response, dlog_proof) =
            oprf_service.answer_query_with_proof(blinded_oprf_query);

        let client_pk = Affine::new_unchecked(query_proof_input.pk[0], query_proof_input.pk[1]);
        let oprf_client = OPrfClient::new(client_pk);

        // We need an intermediate result
        let unblinded_response = (oprf_blinded_response.blinded_response
            * blinding_factor_prepared.factor)
            .into_affine();

        let repsponse = oprf_client
            .finalize_query(oprf_blinded_response.to_owned(), blinding_factor_prepared)
            .expect("IDs should match");

        let nullifier = Self::nullifier(action, epoch, repsponse, query_proof_input.index);

        Self {
            nonce: query_proof_input.nonce,
            user_pk: query_proof_input.pk,
            query_s: query_proof_input.s,
            query_r: query_proof_input.r,
            merkle_root: query_proof_input.merkle_root,
            index: query_proof_input.index,
            siblings: query_proof_input.siblings,
            beta: query_proof_input.beta,
            dlog_e: dlog_proof.e,
            dlog_s: dlog_proof.s,
            oprf_response_blinded: [
                oprf_blinded_response.blinded_response.x,
                oprf_blinded_response.blinded_response.y,
            ],
            oprf_response: [unblinded_response.x, unblinded_response.y],
            oprf_pk: [oprf_service.public_key().x, oprf_service.public_key().y],
            nullified_action: action,
            nullified_epoch: epoch,
            nullifier,
        }
    }

    pub fn print(&self) {
        println!("nonce: {}n,", self.nonce);
        println!("user_pk: [{}n, {}n],", self.user_pk[0], self.user_pk[1]);
        println!("query_s: {}n,", self.query_s);
        println!("query_r: [{}n, {}n],", self.query_r[0], self.query_r[1]);
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
        println!("dlog_e: {}n,", self.dlog_e);
        println!("dlog_s: {}n,", self.dlog_s);
        println!("oprf_pk: [{}n, {}n],", self.oprf_pk[0], self.oprf_pk[1]);
        println!(
            "oprf_response_blinded: [{}n, {}n],",
            self.oprf_response_blinded[0], self.oprf_response_blinded[1]
        );
        println!(
            "oprf_response: [{}n, {}n],",
            self.oprf_response[0], self.oprf_response[1]
        );
        println!("nullified_action: {}n,", self.nullified_action);
        println!("nullified_epoch: {}n,", self.nullified_epoch);
        println!("nullifier: {}n,", self.nullifier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;

    #[test]
    fn test_nullifier_proof_input_10() {
        let seed = array::from_fn(|i| i as u8);
        let input1 = NullifierProofInput::<10>::generate_from_seed(&seed);
        input1.print();
    }
}
