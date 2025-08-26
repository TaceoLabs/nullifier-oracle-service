use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand, Zero};
use rand::{CryptoRng, Rng};
use uuid::Uuid;

use crate::dlog_equality::DLogEqualityProof;

type Curve = ark_babyjubjub::EdwardsProjective;
type ScalarField = <Curve as PrimeGroup>::ScalarField;
type BaseField = <Curve as CurveGroup>::BaseField;
type Affine = <Curve as CurveGroup>::Affine;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OPrfError {
    #[error(
        "Request ID mismatch: The provided blinding factor does not match the request ID in the response."
    )]
    RequestIdMismatch,
    #[error("Invalid proof: The provided DLOG equality proof is invalid.")]
    InvalidProof,
}

pub struct OPrfKey {
    /// secret scalar for the OPRF
    key: ScalarField,
}

impl OPrfKey {
    pub fn new(key: ScalarField) -> Self {
        OPrfKey { key }
    }

    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let key = ScalarField::rand(rng);
        OPrfKey { key }
    }

    pub fn public_key(&self) -> Curve {
        Curve::generator() * self.key
    }
}

pub struct OPrfService {
    /// the OPrf key used for the service
    key: OPrfKey,
    /// the public key derived from the OPrf key, cached for convenience
    public_key: Affine,
}

impl OPrfService {
    pub fn new(key: OPrfKey) -> Self {
        let public_key = key.public_key().into_affine();
        OPrfService { key, public_key }
    }

    pub fn key(&self) -> &OPrfKey {
        &self.key
    }

    pub fn public_key(&self) -> &Affine {
        &self.public_key
    }

    pub fn answer_query(&self, query: BlindedOPrfRequest) -> BlindedOPrfResponse {
        // Compute the blinded response
        let blinded_response = (query.blinded_query * self.key.key).into_affine();
        BlindedOPrfResponse {
            request_id: query.request_id,
            blinded_response,
        }
    }
    pub fn answer_query_with_proof(
        &self,
        query: BlindedOPrfRequest,
    ) -> (BlindedOPrfResponse, DLogEqualityProof) {
        // Compute the blinded response
        let blinded_response = (query.blinded_query * self.key.key).into_affine();

        let proof =
            DLogEqualityProof::proof(query.blinded_query, self.key.key, &mut rand::thread_rng());
        (
            BlindedOPrfResponse {
                request_id: query.request_id,
                blinded_response,
            },
            proof,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOPrfRequest {
    /// request id
    request_id: Uuid,
    /// the blinded query
    blinded_query: Affine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactor {
    /// the blinding factor used to blind the query
    factor: ScalarField,
    /// original query
    query: BaseField,
    // request id, to track the response to the request
    request_id: Uuid,
}
impl BlindingFactor {
    pub fn prepare(self) -> PreparedBlindingFactor {
        PreparedBlindingFactor {
            factor: self
                .factor
                .inverse()
                .expect("Blinding factor should not be zero"),
            request_id: self.request_id,
            query: self.query,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBlindingFactor {
    /// the inverse of the blinding factor used to blind the query
    factor: ScalarField,
    /// original query
    query: BaseField,
    // request id, to track the response to the request
    request_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedOPrfResponse {
    /// request id, to track the response to the request
    request_id: Uuid,
    /// the blinded response
    blinded_response: Affine,
}

pub struct OPrfClient {
    /// the public key of the OPrf service
    public_key: Affine,
}

impl OPrfClient {
    pub fn new(public_key: Affine) -> Self {
        OPrfClient { public_key }
    }

    /// Blinds a query for the OPRF service, generating a blinding factor and a request ID.
    /// The provided query field element is mapped to a point on the curve, using Elligator2 based methods.
    pub fn blind_query<R: Rng + CryptoRng>(
        &self,
        query: BaseField,
        rng: &mut R,
    ) -> (BlindedOPrfRequest, BlindingFactor) {
        // Generate a random blinding factor and request ID
        let blinding_factor = loop {
            let random = ScalarField::rand(rng);
            if !random.is_zero() {
                break random;
            }
        };
        let request_id = Uuid::new_v4();

        let encoded_input = mappings::encode_to_curve(query);

        let blinded_query = (encoded_input * blinding_factor).into_affine();
        (
            BlindedOPrfRequest {
                request_id,
                blinded_query,
            },
            BlindingFactor {
                factor: blinding_factor,
                query,
                request_id,
            },
        )
    }

    pub fn finalize_query(
        &self,
        response: BlindedOPrfResponse,
        blinding_factor: PreparedBlindingFactor,
    ) -> Result<BaseField, OPrfError> {
        // Unblind the response using the blinding factor
        if response.request_id != blinding_factor.request_id {
            return Err(OPrfError::RequestIdMismatch);
        }
        let unblinded_response = response.blinded_response * blinding_factor.factor;
        let unblinded_point = unblinded_response.into_affine();

        // compute the second hash in the 2Hash-DH construction
        // out = H(query, unblinded_point)
        let hash_input = [
            BaseField::zero(), // capacity of the sponge
            blinding_factor.query,
            unblinded_point.x,
            unblinded_point.y,
        ];

        let poseidon = poseidon2::Poseidon2::new(&poseidon2::POSEIDON2_BN254_PARAMS_4);
        let output = poseidon.permutation(&hash_input);
        Ok(output[1]) // Return the first element of the state as the field element,
    }

    pub fn finalize_query_and_verify_proof(
        &self,
        response: BlindedOPrfResponse,
        proof: DLogEqualityProof,
        blinding_factor: PreparedBlindingFactor,
    ) -> Result<BaseField, OPrfError> {
        // Verify the proof
        let d = Curve::generator().into_affine();
        let a = self.public_key;
        //TODO: save this element to avoid recomputing it?
        let b = (mappings::encode_to_curve(blinding_factor.query)
            * blinding_factor.factor.inverse().unwrap())
        .into_affine();
        let c = response.blinded_response;

        if !proof.verify(a, b, c, d) {
            return Err(OPrfError::InvalidProof);
        }
        // Call finalize_query to unblind the response
        self.finalize_query(response, blinding_factor)
    }
}

mod mappings {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
    use poseidon2::POSEIDON2_BN254_PARAMS_3;

    use crate::oprf::{Affine, BaseField};

    /// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
    ///
    /// As mentioned in the RFC, this encoding is non uniformly random in E, as this can only hit about half of the of the curve points.
    pub fn encode_to_curve(input: BaseField) -> Affine {
        // Map the input to a point on the curve using Elligator2
        let u = hash_to_field(input);
        let q = map_to_curve_twisted_edwards(u);
        q.clear_cofactor()
    }

    /// A curve encoding function that maps a field element to a point on the curve, based on [RFC9380, Section 3](https://www.rfc-editor.org/rfc/rfc9380.html#name-encoding-byte-strings-to-el).
    ///
    /// In contrast to `encode_to_curve`, this function uses a two-step mapping to ensure that the output is uniformly random over the curve.
    pub fn hash_to_curve(input: BaseField) -> Affine {
        // Map the input to a point on the curve using Elligator2
        let [u0, u1] = hash_to_field2(input);
        let q0 = map_to_curve_twisted_edwards(u0);
        let q1 = map_to_curve_twisted_edwards(u1);
        let r = (q0 + q1).into_affine();
        r.clear_cofactor()
    }

    /// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
    fn hash_to_field(input: BaseField) -> BaseField {
        // hash the input to a field element using poseidon hash
        let poseidon = poseidon2::Poseidon2::new(&POSEIDON2_BN254_PARAMS_3);
        let output = poseidon.permutation(&[BaseField::zero(), input, BaseField::zero()]);
        output[1] // Return the first element of the state as the field element, element 0 is the capacity of the sponge
    }

    /// An implementation of `hash_to_field` based on [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
    fn hash_to_field2(input: BaseField) -> [BaseField; 2] {
        // hash the input to a field element using poseidon hash
        let poseidon = poseidon2::Poseidon2::new(&POSEIDON2_BN254_PARAMS_3);
        let output = poseidon.permutation(&[BaseField::zero(), input, BaseField::zero()]);

        [output[1], output[2]] // Return the first two elements of the state as the field elements, element 0 is the capacity of the sponge
    }

    /// Maps the input to a point on the curve, without anyone knowing the DLOG of the curve point.
    ///
    /// This is based on `map_to_curve` from [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    /// We use section 6.8 ("Mappings for Twisted Edwards Curves") to map the input to a point on the curve.
    /// This internally uses a birationally equivalent Montgomery curve to perform the mapping, then uses a rational map to convert the point to the Edwards curve.
    fn map_to_curve_twisted_edwards(input: BaseField) -> Affine {
        let (s, t) = map_to_curve_elligator2(input);
        let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
        Affine { x: v, y: w }
    }

    /// Maps the input to a point on the Montgomery curve, without anyone knowing the DLOG of the curve point.
    ///
    /// Returns the s and t coordinates of the point on the Montgomery curve.
    ///
    /// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$.
    /// We follow the Elligator2 mapping as described in [RFC9380, Section 6.7.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method).
    fn map_to_curve_elligator2(input: BaseField) -> (BaseField, BaseField) {
        // constant c1 = J/K;
        let j = BaseField::from(168698);
        let k = BaseField::from(1);
        let c1 = j / k;
        // constant c2 = 1/ K^2
        let c2 = (k * k).inverse().unwrap();
        // constant Z = 5, based on RFC9380, Appendix H.3.
        // ```sage
        // # Argument:
        // # - F, a field object, e.g., F = GF(2^255 - 19)
        // def find_z_ell2(F):
        //     ctr = F.gen()
        //     while True:
        //         for Z_cand in (F(ctr), F(-ctr)):
        //             # Z must be a non-square in F.
        //             if is_square(Z_cand):
        //                 continue
        //             return Z_cand
        //         ctr += 1
        // # BaseField of Baby JubJub curve:
        // F = GF(21888242871839275222246405745257275088548364400416034343698204186575808495617)
        // find_z_ell2(F) # 5
        // ```
        let z = BaseField::from(5);
        let tv1 = input * input;
        let tv1 = z * tv1;
        // TODO: constant-time
        let e = (tv1 + BaseField::one()).is_zero();
        let tv1 = if e { BaseField::zero() } else { tv1 };
        let x1 = tv1 + BaseField::one();
        let x1 = inv0(x1);
        let x1 = -c1 * x1;
        let gx1 = x1 + c1;
        let gx1 = gx1 * x1;
        let gx1 = gx1 + c2;
        let gx1 = gx1 * x1;
        let x2 = -x1 - c1;
        let gx2 = tv1 * gx1;
        // TODO: constant time
        let e2 = gx1.sqrt().is_some();
        let (x, y2) = if e2 { (x1, gx1) } else { (x2, gx2) };
        let y = y2
            .sqrt()
            .expect("y2 should be a square based on our conditional selection above");
        let e3 = sgn0(y);
        // TODO: constant-time
        let y = if e2 ^ e3 { -y } else { y };
        let s = x * k;
        let t = y * k;
        (s, t)
    }

    /// Converts a point from Montgomery to Twisted Edwards using the rational map.
    ///
    /// This is based on appendix D1 of [RFC9380](https://www.rfc-editor.org/rfc/rfc9380.html).
    ///
    /// Let the twisted Edwards curve be defined by the equation $a*v^2 + w^2 = 1 + d*v^2*w^2$.
    /// let the Montgomery curve be defined by the equation $K*t^2 = s^3 + J*s^2 + s$, with
    /// $J = 2 * (a + d) / (a - d)$ and $K = 4 / (a - d)$.
    ///
    /// For the concrete case of Baby JubJub, we have:
    /// - $K = 1$
    /// - $J = 168698$
    /// - $a = 168700$
    /// - $d = 168696$
    ///
    /// Input: (s, t), a point on the curve $K * t^2 = s^3 + J * s^2 + s$.
    /// Output: (v, w), a point on the equivalent twisted Edwards curve.
    /// (This function also handles exceptional cases where the point is at infinity correctly.)
    fn rational_map_mont_to_twisted_edwards(s: BaseField, t: BaseField) -> (BaseField, BaseField) {
        // Convert the point from Montgomery to Twisted Edwards using the rational map
        let tv1 = s + BaseField::one();
        let tv2 = tv1 * t;
        let tv2 = inv0(tv2);
        let v = tv1 * tv2;
        let v = v * s;
        let w = tv2 * t;
        let tv1 = s - BaseField::one();
        let w = w * tv1;
        // TODO: make constant-time
        let e = tv2.is_zero();
        let w = if e { BaseField::one() } else { w };
        (v, w)
    }

    /// Computes the inverse of a field element, returning zero if the element is zero.
    fn inv0<F: PrimeField>(x: F) -> F {
        x.inverse().unwrap_or(F::zero())
    }

    /// Computes the `sgn0` function for a field element, based on the definition in [RFC9380, Section 4.1](https://www.rfc-editor.org/rfc/rfc9380.html#name-the-sgn0-function).
    fn sgn0<F: PrimeField>(x: F) -> bool {
        x.into_bigint().is_odd()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_ff::UniformRand;

        #[test]
        fn test_map_to_curve_twisted_edwards() {
            let input = BaseField::from(42);
            let (s, t) = map_to_curve_elligator2(input);
            let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
            let point = Affine { x: v, y: w };
            assert!(point.is_on_curve());
        }
        #[test]
        fn test_map_to_curve_twisted_edwards_rand() {
            for _ in 0..100 {
                // Test with random inputs
                let input = BaseField::rand(&mut rand::thread_rng());
                let (s, t) = map_to_curve_elligator2(input);
                let (v, w) = rational_map_mont_to_twisted_edwards(s, t);
                let point = Affine { x: v, y: w };
                assert!(point.is_on_curve(), "Failed for input: {:?}", input);
            }
        }

        #[test]
        fn test_encode_to_curve() {
            let input = BaseField::from(42);
            let point = encode_to_curve(input);
            assert!(point.is_on_curve());
        }
        #[test]
        fn test_hash_to_curve() {
            let input = BaseField::from(42);
            let point = hash_to_curve(input);
            assert!(point.is_on_curve());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_determinism() {
        let mut rng = rand::thread_rng();
        let key = OPrfKey::random(&mut rng);
        let service = OPrfService::new(key);
        let client = OPrfClient::new(*service.public_key());

        let query = BaseField::from(42);
        let (blinded_request, blinding_factor) = client.blind_query(query, &mut rng);
        let (blinded_request2, blinding_factor2) = client.blind_query(query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        assert_ne!(
            blinded_request.blinded_query,
            blinded_request2.blinded_query
        );
        let response = service.answer_query(blinded_request);

        let response = client
            .finalize_query(response, blinding_factor.prepare())
            .unwrap();

        let expected_response = (mappings::encode_to_curve(query) * service.key.key).into_affine();
        let poseidon = poseidon2::Poseidon2::new(&poseidon2::POSEIDON2_BN254_PARAMS_4);
        let out = poseidon.permutation(&[
            BaseField::zero(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(response, expected_output);
        let response2 = service.answer_query(blinded_request2);

        let unblinded_response2 = client
            .finalize_query(response2, blinding_factor2.prepare())
            .unwrap();
        assert_eq!(response, unblinded_response2);
    }

    #[test]
    fn test_oprf_with_proof() {
        let mut rng = rand::thread_rng();
        let key = OPrfKey::random(&mut rng);
        let service = OPrfService::new(key);
        let client = OPrfClient::new(*service.public_key());

        let query = BaseField::from(42);
        let (blinded_request, blinding_factor) = client.blind_query(query, &mut rng);
        let (blinded_request2, blinding_factor2) = client.blind_query(query, &mut rng);
        assert_ne!(blinded_request, blinded_request2);
        assert_ne!(
            blinded_request.blinded_query,
            blinded_request2.blinded_query
        );
        let (response, proof) = service.answer_query_with_proof(blinded_request);

        let unblinded_response = client
            .finalize_query_and_verify_proof(
                response.clone(),
                proof,
                blinding_factor.clone().prepare(),
            )
            .unwrap();

        let expected_response = (mappings::encode_to_curve(query) * service.key.key).into_affine();
        let poseidon = poseidon2::Poseidon2::new(&poseidon2::POSEIDON2_BN254_PARAMS_4);
        let out = poseidon.permutation(&[
            BaseField::zero(),
            query,
            expected_response.x,
            expected_response.y,
        ]);
        let expected_output = out[1];

        assert_eq!(unblinded_response, expected_output);

        let (response2, proof2) = service.answer_query_with_proof(blinded_request2);
        let unblinded_response2 = client
            .finalize_query_and_verify_proof(response2, proof2.clone(), blinding_factor2.prepare())
            .unwrap();
        assert_eq!(unblinded_response, unblinded_response2);

        assert_eq!(
            client.finalize_query_and_verify_proof(response, proof2, blinding_factor.prepare()),
            Err(OPrfError::InvalidProof)
        );
    }
}
