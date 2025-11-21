//! This module implements the client side of the OPRF protocol, including query construction, blinding and unblinding,
//! as well as proof verification. It provides methods to generate domain-separated queries, blind them using random factors,
//! finalize (unblind and hash) server responses, and verify server proofs of correctness.

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use rand::{CryptoRng, Rng};

use crate::dlog_equality::{DLogEqualityProof, InvalidProof};

use crate::oprf::{
    Affine, BaseField, BlindedOprfRequest, BlindedOprfResponse, BlindingFactor, Curve,
    PreparedBlindingFactor, ScalarField, mappings,
};

const OPRF_DS: &[u8] = b"World ID Proof";
const QUERY_DS: &[u8] = b"World ID Query";
const ID_COMMITMENT_DS: &[u8] = b"H(id, r)";

/// Returns the domain separator ("World ID Proof") for the query finalization as a field element.
pub fn get_oprf_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(OPRF_DS)
}

/// Returns the domain separator ("World ID Query") for the query generation as a field element
pub fn get_query_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(QUERY_DS)
}

/// Returns the domain separator ("H(id, r)") for the id commitment as a field element
pub fn get_id_commitment_ds() -> BaseField {
    BaseField::from_be_bytes_mod_order(ID_COMMITMENT_DS)
}

/// Generates a domain-separated query field element from the provided `index`, `rp_id`, and `action` using the Poseidon2 permutation.
///
/// Computes `P(b"World ID Query", index, rp_id, action)` with a domain separator, and returns the first output element (index 1) as the query input.
///
/// # Arguments
///
/// * `index` - User or credential index.
/// * `rp_id` - Relying party identifier.
/// * `action` - Action code.
///
/// # Returns
///
/// A `BaseField` element representing the domain-separated OPRF query input.
pub fn generate_query(index: BaseField, rp_id: BaseField, action: BaseField) -> BaseField {
    // capacity of the sponge has domain separator
    let input = [get_query_ds(), index, rp_id, action];
    poseidon2::bn254::t4::permutation(&input)[1]
}

/// Blinds a query for the OPRF server using a randomly generated blinding factor.
///
/// The query is mapped to a curve point, then blinded via scalar multiplication.
/// Returns the blinded request and the blinding factor.
///
/// # Arguments
///
/// * `query` - Query field element to be blinded.
/// * `rng` - Cryptographically secure random number generator.
///
/// # Returns
///
/// Tuple of [`BlindedOprfRequest`] and [`BlindingFactor`].
pub fn blind_query<R: Rng + CryptoRng>(
    query: BaseField,
    rng: &mut R,
) -> (BlindedOprfRequest, BlindingFactor) {
    // Generate a random blinding factor
    // The blinding factor shall not be zero. As the chance of getting a zero is negligible, we don't perform a check here.
    let blinding_factor = ScalarField::rand(rng);
    let encoded_input = mappings::encode_to_curve(query);
    let blinded_query = (encoded_input * blinding_factor).into_affine();
    (
        BlindedOprfRequest(blinded_query),
        BlindingFactor {
            factor: blinding_factor,
            query,
        },
    )
}

/// Unblinds an OPRF server response and hashes it to produce the final output for the query. This method is for the non-threshold variant of the OPRF protocol.
///
/// Performs 2Hash-DH: H(query, unblinded_point).
///
/// # Arguments
///
/// * `response` - Blinded OPRF server response.
/// * `blinding_factor` - Prepared blinding factor for unblinding.
///
/// # Returns
///
/// OPRF output as a `BaseField` element.
pub fn finalize_query(
    response: BlindedOprfResponse,
    blinding_factor: PreparedBlindingFactor,
) -> BaseField {
    // Unblind the response using the blinding factor
    let unblinded_point = response.unblind_response(&blinding_factor);

    // compute the second hash in the 2Hash-DH construction
    // out = H(query, unblinded_point)
    let hash_input = [
        get_oprf_ds(), // capacity of the sponge with domain separator
        blinding_factor.query,
        unblinded_point.x,
        unblinded_point.y,
    ];

    let output = poseidon2::bn254::t4::permutation(&hash_input);
    output[1] // Return the first element of the state as the field element,
}

/// Unblinds a response, verifies the discrete log equality proof, and produces the final OPRF output. This method is for the non-threshold variant of the OPRF protocol.
///
/// Calls [`finalize_query`] after verifying the proof.
///
/// # Arguments
///
/// * `a` - Prover's public parameter.
/// * `response` - Blinded OPRF server response.
/// * `proof` - Discrete log equality proof.
/// * `blinding_factor` - Prepared blinding factor for unblinding.
///
/// # Returns
///
/// Returns the OPRF output if the proof is valid, else returns `InvalidProof`.
pub fn finalize_query_and_verify_proof(
    a: Affine,
    response: BlindedOprfResponse,
    proof: DLogEqualityProof,
    blinding_factor: PreparedBlindingFactor,
) -> Result<BaseField, InvalidProof> {
    // Verify the proof
    use ark_ec::PrimeGroup as _;
    use ark_ff::Field as _;
    let d = Curve::generator().into_affine();
    let b = (mappings::encode_to_curve(blinding_factor.query)
        * blinding_factor.factor.inverse().unwrap())
    .into_affine();
    let c = response.0;

    proof.verify(a, b, c, d)?;

    // Call finalize_query to unblind the response
    Ok(finalize_query(response, blinding_factor))
}
