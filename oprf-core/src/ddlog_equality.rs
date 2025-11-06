use crate::dlog_equality::DLogEqualityProof;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDLogEqualityCommitments {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) c: Affine, // The share of the actual result C=B*x
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The share of G*d1, the first part of the two-nonce commitment to the randomness r1 = d1 + e1*b
    pub(crate) d1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The share of G*d2, the first part of the two-nonce commitment to the randomness r2 = d2 + e2*b
    pub(crate) d2: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The share of G*e1, the second part of the two-nonce commitment to the randomness r1 = d1 + e1*b
    pub(crate) e1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The share of G*e2, the second part of the two-nonce commitment to the randomness r2 = d2 + e2*b
    pub(crate) e2: Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLogEqualityCommitments {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub(crate) c: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The aggregated G*d1.
    pub(crate) d1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The aggregated G*d2.
    pub(crate) d2: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The aggregated G*e1.
    pub(crate) e1: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The aggregated G*e2.
    pub(crate) e2: Affine,
    /// The parties that contributed to this commitment.
    pub(crate) contributing_parties: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLogEqualityProofShare {
    // The share of the response s
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fr")]
    pub(crate) s: ScalarField,
}

/// The internal storage of a party in a distributed DlogEqualityProof protocol.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. We also don't implement `Debug` so we do don't print it by accident.
/// The `challenge` method consumes the session.
#[derive(ZeroizeOnDrop)]
pub struct DLogEqualitySession {
    pub(crate) d: ScalarField,
    pub(crate) e: ScalarField,
    pub(crate) blinded_query: Affine,
}

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

impl DLogEqualitySession {
    /// Computes C=B·x_share and commitments to two random values d_share and e_share, which will be the shares of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        x_share: ScalarField,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogEqualityCommitments) {
        let d_share = ScalarField::rand(rng);
        let e_share = ScalarField::rand(rng);
        let d1 = (Affine::generator() * d_share).into_affine();
        let e1 = (Affine::generator() * e_share).into_affine();
        let d2 = (b * d_share).into_affine();
        let e2 = (b * e_share).into_affine();
        let c_share = (b * x_share).into_affine();

        let comm = PartialDLogEqualityCommitments {
            c: c_share,
            d1,
            d2,
            e1,
            e2,
        };

        let session = DLogEqualitySession {
            d: d_share,
            e: e_share,
            blinded_query: b,
        };

        (session, comm)
    }

    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    pub fn challenge(
        self,
        session_id: Uuid,
        contributing_parties: &[u16],
        x_share: ScalarField,
        a: Affine,
        challenge_input: DLogEqualityCommitments,
    ) -> DLogEqualityProofShare {
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r1, r2, b) = combine_twononce_randomness(
            session_id,
            a,
            challenge_input.c,
            challenge_input.d1,
            challenge_input.d2,
            challenge_input.e1,
            challenge_input.e2,
            contributing_parties,
        );

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(
            a,
            self.blinded_query,
            challenge_input.c,
            d,
            r1,
            r2,
        );

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = crate::dlog_equality::convert_base_to_scalar(e);
        DLogEqualityProofShare {
            s: self.d + b * self.e + e_ * x_share,
        }
    }
}

impl DLogEqualityCommitments {
    pub fn new(
        c: Affine,
        d1: Affine,
        d2: Affine,
        e1: Affine,
        e2: Affine,
        parties: Vec<u16>,
    ) -> Self {
        DLogEqualityCommitments {
            c,
            d1,
            d2,
            e1,
            e2,
            contributing_parties: parties,
        }
    }

    /// Returns the parties that contributed to this commitment.
    pub fn get_contributing_parties(&self) -> &[u16] {
        &self.contributing_parties
    }

    /// The accumulating party (e.g., the verifier) combines all the shares of all parties.
    /// The returned points are the combined commitments C, R1, R2.
    pub fn combine_commitments(commitments: &[(u16, PartialDLogEqualityCommitments)]) -> Self {
        let mut c = Projective::zero();
        let mut d1 = Projective::zero();
        let mut d2 = Projective::zero();
        let mut e1 = Projective::zero();
        let mut e2 = Projective::zero();
        let mut contributing_parties = Vec::with_capacity(commitments.len());

        for (party_id, comm) in commitments {
            c += comm.c;
            d1 += comm.d1;
            d2 += comm.d2;
            e1 += comm.e1;
            e2 += comm.e2;
            contributing_parties.push(*party_id);
        }

        let c = c.into_affine();
        let d1 = d1.into_affine();
        let d2 = d2.into_affine();
        let e1 = e1.into_affine();
        let e2 = e2.into_affine();

        DLogEqualityCommitments {
            c,
            d1,
            d2,
            e1,
            e2,
            contributing_parties,
        }
    }

    pub fn combine_proofs(
        self,
        session_id: Uuid,
        contributing_parties: &[u16],
        proofs: &[DLogEqualityProofShare],
        a: Affine,
        b: Affine,
    ) -> DLogEqualityProof {
        let mut s = ScalarField::zero();
        for proof in proofs {
            s += proof.s;
        }
        let (r1, r2, _) = combine_twononce_randomness(
            session_id,
            a,
            self.c,
            self.d1,
            self.d2,
            self.e1,
            self.e2,
            contributing_parties,
        );

        let d = Affine::generator();
        let e = crate::dlog_equality::challenge_hash(a, b, self.c, d, r1, r2);

        DLogEqualityProof { e, s }
    }

    /// Returns the combined blinded response C=B*x.
    pub fn blinded_response(&self) -> Affine {
        self.c
    }
}

const FROST_2_NONCE_COMBINER_LABEL: &[u8] = b"FROST_2_NONCE_COMBINER";

#[allow(clippy::too_many_arguments)]
/// Combines the two-nonce randomness shares into the full randomness used in the challenge.
/// Returns (r1, r2, b) where r1 = d1 + e1*b and r2 = d2 + e2*b
pub(crate) fn combine_twononce_randomness(
    session_id: Uuid,
    public_key: Affine,
    oprf_output: Affine,
    d1: Affine,
    d2: Affine,
    e1: Affine,
    e2: Affine,
    parties: &[u16],
) -> (Affine, Affine, ScalarField) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FROST_2_NONCE_COMBINER_LABEL);
    hasher.update(session_id.as_bytes());
    for party in parties {
        hasher.update(&party.to_le_bytes());
    }
    let mut buf = Vec::with_capacity(d1.compressed_size());

    // serialize an Affine point in canonical compressed form
    let mut serialize_point = |point: &Affine| {
        point
            .serialize_compressed(&mut buf)
            .expect("can serialize point into a vec");
        hasher.update(&buf);
        buf.clear();
    };
    serialize_point(&public_key);
    serialize_point(&oprf_output);
    serialize_point(&d1);
    serialize_point(&d2);
    serialize_point(&e1);
    serialize_point(&e2);

    let mut hash_output = hasher.finalize_xof();

    // We use 64 bytes to have enough statistical security against modulo bias
    let mut unreduced_b = [0u8; 64];
    hash_output.fill(&mut unreduced_b);

    let b = ScalarField::from_le_bytes_mod_order(&unreduced_b);
    let r1 = d1 + e1 * b;
    let r2 = d2 + e2 * b;
    (r1.into_affine(), r2.into_affine(), b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_distributed_dlog_equality(num_parties: usize) {
        let mut rng = rand::thread_rng();

        // Random x shares
        let x_shares = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();

        // Combine x shares
        let x = x_shares.iter().fold(ScalarField::zero(), |acc, x| acc + x);

        // Create public keys
        let public_key = (Affine::generator() * x).into_affine();
        let public_key_ = x_shares
            .iter()
            .map(|x| (Affine::generator() * x).into_affine())
            .fold(Projective::zero(), |acc, x| acc + x)
            .into_affine();
        assert_eq!(public_key, public_key_);

        // Crete session
        let session_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for (id, &x_) in x_shares.iter().enumerate() {
            let (session, comm) = DLogEqualitySession::partial_commitments(b, x_, &mut rng);
            sessions.push(session);
            commitments.push((id as u16 + 1, comm));
        }

        // 2) Client accumulates commitments and creates challenge
        let challenge = DLogEqualityCommitments::combine_commitments(&commitments);
        let c = challenge.blinded_response();

        // 3) Client challenges all servers
        let contributing_parties = (1u16..=(num_parties as u16)).collect::<Vec<_>>();
        let mut proofs = Vec::with_capacity(num_parties);
        for (session, x_) in sessions.into_iter().zip(x_shares.iter().cloned()) {
            let proof = session.challenge(
                session_id,
                &contributing_parties,
                x_,
                public_key,
                challenge.to_owned(),
            );
            proofs.push(proof);
        }

        // 4) Client combines all proofs
        let proof =
            challenge.combine_proofs(session_id, &contributing_parties, &proofs, public_key, b);

        // Verify the result and the proof
        let d = Affine::generator();
        assert_eq!(c, b * x, "Result must be correct");
        assert!(
            proof.verify(public_key, b, c, d),
            "valid proof should verify"
        );
    }

    #[test]
    fn test_distributed_dlog_equality_3_parties() {
        test_distributed_dlog_equality(3);
    }

    #[test]
    fn test_distributed_dlog_equality_30_parties() {
        test_distributed_dlog_equality(30);
    }
}
