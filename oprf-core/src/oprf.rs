//! This module defines the core functionality of the OPRF protocol.
//!
//! It provides types for representing client queries, blinding factors, and blinded server responses.
//!
//! Blinding is used to ensure the server cannot learn the client’s input. The roundtrip uses a blinding factor to blind queries,
//! and unblinding after server response to recover the OPRF output. This module is shared between both the client and, under the
//! `server` feature, the server implementations.
//!
//! See the `client` module for client-side helpers, and the `server` module (when enabled) for non-threshold server operations.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;

pub(crate) type Affine = <Curve as CurveGroup>::Affine;
pub(crate) type BaseField = <Curve as CurveGroup>::BaseField;
pub(crate) type Curve = ark_babyjubjub::EdwardsProjective;
pub(crate) type Projective = ark_babyjubjub::EdwardsProjective;
pub(crate) type ScalarField = <Curve as PrimeGroup>::ScalarField;

pub mod client;
mod mappings;
#[cfg(feature = "server")]
pub mod server;

/// A blinded OPRF client request, containing the curve point encoding the blinded query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOprfRequest(Affine);

impl BlindedOprfRequest {
    /// Returns the public x/y coordinates of the blinded query.
    pub fn blinded_query_as_public_output(&self) -> [BaseField; 2] {
        [self.0.x, self.0.y]
    }

    /// Returns the blinded query as an affine curve point.
    pub fn blinded_query(&self) -> Affine {
        self.0
    }
}

/// The OPRF query blinding factor, as well as the original query value.
///
/// The blinding factor shall not be zero, otherwise [`BlindingFactor::prepare`] will panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactor {
    /// The scalar blinding factor used to blind the query.
    factor: ScalarField,
    /// The original (unblinded) query field element.
    query: BaseField,
}

impl BlindingFactor {
    /// Prepare the blinding factor for unblinding (by inverting the blinding scalar).
    ///
    /// # Panics
    /// This method panics if the blinding factor is 0.
    pub fn prepare(self) -> PreparedBlindingFactor {
        PreparedBlindingFactor {
            factor: self
                .factor
                .inverse()
                .expect("Blinding factor should not be zero"),
            query: self.query,
        }
    }

    /// Returns the (non-inverted) blinding factor.
    pub fn beta(&self) -> ScalarField {
        self.factor
    }

    /// Returns the original query.
    pub fn query(&self) -> BaseField {
        self.query
    }
}

/// Prepared blinding factor, storing the inverse for unblinding as well as the original query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBlindingFactor {
    /// The inverse of the blinding factor used for unblinding.
    factor: ScalarField,
    /// The original query value.
    query: BaseField,
}

/// The blinded OPRF response from the server, as an affine curve point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOprfResponse(Affine);

impl BlindedOprfResponse {
    /// Construct a new blinded response from an affine point.
    pub fn new(p: Affine) -> Self {
        Self(p)
    }

    /// Unblind the server response using the prepared blinding factor.
    pub fn unblind_response(&self, blinding_factor: &PreparedBlindingFactor) -> Affine {
        (self.0 * blinding_factor.factor).into_affine()
    }

    /// Return the affine curve point of the response.
    pub fn response(&self) -> Affine {
        self.0
    }
}

#[cfg(test)]
#[cfg(feature = "server")]
mod tests {
    use poseidon2::Poseidon2;

    use crate::oprf::{
        self,
        server::{OprfKey, OprfServer},
    };

    use super::*;

    #[test]
    fn test_oprf_determinism() {
        let mut rng = rand::thread_rng();
        let key = OprfKey::random(&mut rng);
        let service = OprfServer::new(key);

        let query = oprf::client::generate_query(
            BaseField::from(42),
            BaseField::from(2),
            BaseField::from(3),
        );
        let (blinded_request, blinding_factor) = oprf::client::blind_query(query, &mut rng);
        let (blinded_request2, blinding_factor2) = oprf::client::blind_query(query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        let response = service.answer_query(blinded_request);

        let response = oprf::client::finalize_query(response, blinding_factor.prepare());

        let expected_response = &service.key * mappings::encode_to_curve(query);
        let poseidon = Poseidon2::<_, 4, 5>::default();
        let out = poseidon.permutation(&[
            oprf::client::get_oprf_ds(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(response, expected_output);
        let response2 = service.answer_query(blinded_request2);

        let unblinded_response2 =
            oprf::client::finalize_query(response2, blinding_factor2.prepare());
        assert_eq!(response, unblinded_response2);
    }

    #[test]
    fn test_oprf_with_proof() {
        let mut rng = rand::thread_rng();
        let key = OprfKey::random(&mut rng);
        let service = OprfServer::new(key);
        let public_key = service.public_key();

        let query = oprf::client::generate_query(
            BaseField::from(42),
            BaseField::from(2),
            BaseField::from(3),
        );
        let (blinded_request, blinding_factor) = oprf::client::blind_query(query, &mut rng);
        let (blinded_request2, blinding_factor2) = oprf::client::blind_query(query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        let (response, proof) = service.answer_query_with_proof(blinded_request);

        let unblinded_response = oprf::client::finalize_query_and_verify_proof(
            public_key,
            response.clone(),
            proof,
            blinding_factor.clone().prepare(),
        )
        .unwrap();

        let expected_response = &service.key * mappings::encode_to_curve(query);
        let poseidon = Poseidon2::<_, 4, 5>::default();
        let out = poseidon.permutation(&[
            oprf::client::get_oprf_ds(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(unblinded_response, expected_output);

        let (response2, proof2) = service.answer_query_with_proof(blinded_request2);
        let unblinded_response2 = oprf::client::finalize_query_and_verify_proof(
            public_key,
            response2,
            proof2.clone(),
            blinding_factor2.prepare(),
        )
        .unwrap();
        assert_eq!(unblinded_response, unblinded_response2);

        oprf::client::finalize_query_and_verify_proof(
            public_key,
            response,
            proof2,
            blinding_factor.prepare(),
        )
        .unwrap_err();
    }
}
