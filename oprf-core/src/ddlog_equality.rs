use crate::{dlog_equality::DLogEqualityProof, oprf::OPrfError};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{UniformRand, Zero};
use rand::{CryptoRng, Rng};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PartialDLogEqualityCommitments {
    request_id: Uuid,
    c: Affine, // The share of the actual result C=B*x
    r1: Affine,
    r2: Affine,
}

#[derive(Debug, Clone)]

pub struct DLogEqualityChallenge {
    request_id: Uuid,
    e: BaseField, // The challenge hash
}

#[derive(Debug, Clone)]

pub struct DLogEqualityProofShare {
    /// request id
    request_id: Uuid,
    s: ScalarField, // The share of the response s
}

#[derive(Debug, Clone)]

pub struct DlogEqualitySession {
    /// request id
    request_id: Uuid,
    /// randomness share used in the proof
    k: ScalarField,
}

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

impl DlogEqualitySession {
    /// Computes C=B*x_share and commitments to a random value k_share, which will be the share of the randomness used in the DlogEqualityProof.
    /// The result is meant to be sent to one accumulating party (e.g., the verifier) who combines all the shares of all parties and creates the challenge hash.
    pub fn partial_commitments(
        b: Affine,
        x_share: ScalarField,
        request_id: Uuid,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialDLogEqualityCommitments) {
        let k_share = ScalarField::rand(rng);
        let r1 = (Projective::generator() * k_share).into_affine();
        let r2 = (b * k_share).into_affine();
        let c_share = (b * x_share).into_affine();

        let comm = PartialDLogEqualityCommitments {
            request_id,
            c: c_share,
            r1,
            r2,
        };

        let session = DlogEqualitySession {
            request_id,
            k: k_share,
        };

        (session, comm)
    }

    pub fn challenge(
        &self,
        x_share: ScalarField,
        challenge: DLogEqualityChallenge,
    ) -> Result<DLogEqualityProofShare, OPrfError> {
        if self.request_id != challenge.request_id {
            return Err(OPrfError::RequestIdMismatch);
        }

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let e_ = crate::dlog_equality::convert_base_to_scalar(challenge.e);
        let s_share = self.k + e_ * x_share;

        Ok(DLogEqualityProofShare {
            request_id: self.request_id,
            s: s_share,
        })
    }
}

impl DLogEqualityChallenge {
    /// The accumulating party (e.g., the verifier) combines all the shares of all parties and creates the challenge hash.
    pub fn combine_commitments_and_create_challenge(
        commitments: &[PartialDLogEqualityCommitments],
        a: Affine, // Combined public key of the provers
        b: Affine,
    ) -> Result<(Affine, Self), OPrfError> {
        let request_id = commitments
            .first()
            .ok_or(OPrfError::RequestIdMismatch)?
            .request_id;
        if commitments
            .iter()
            .skip(1)
            .any(|c| c.request_id != request_id)
        {
            return Err(OPrfError::RequestIdMismatch);
        }

        let mut c = Projective::zero();
        let mut r1 = Projective::zero();
        let mut r2 = Projective::zero();

        for comm in commitments {
            c += comm.c;
            r1 += comm.r1;
            r2 += comm.r2;
        }

        // Create the challenge hash
        let d = Projective::generator().into_affine();
        let c = c.into_affine();
        let r1 = r1.into_affine();
        let r2 = r2.into_affine();

        let e = crate::dlog_equality::challenge_hash(a, b, c, d, r1, r2);

        Ok((c, DLogEqualityChallenge { request_id, e }))
    }

    pub fn combine_proofs(
        &self,
        proofs: &[DLogEqualityProofShare],
    ) -> Result<DLogEqualityProof, OPrfError> {
        let request_id = self.request_id;
        if proofs.iter().any(|p| p.request_id != request_id) {
            return Err(OPrfError::RequestIdMismatch);
        }

        let mut s = ScalarField::zero();
        for proof in proofs {
            s += proof.s;
        }

        Ok(DLogEqualityProof { e: self.e, s })
    }
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
        let public_key = (Projective::generator() * x).into_affine();
        let public_key_ = x_shares
            .iter()
            .map(|x| (Projective::generator() * x).into_affine())
            .fold(Projective::zero(), |acc, x| acc + x)
            .into_affine();
        assert_eq!(public_key, public_key_);

        // Crete session
        let request_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for x_ in x_shares.iter().cloned() {
            let (session, comm) =
                DlogEqualitySession::partial_commitments(b, x_, request_id, &mut rng);
            sessions.push(session);
            commitments.push(comm);
        }

        // 2) Client accumulates commitments and creates challenge
        let (c, challenge) = DLogEqualityChallenge::combine_commitments_and_create_challenge(
            &commitments,
            public_key,
            b,
        )
        .unwrap();

        // 3) Client challenges all servers
        let mut proofs = Vec::with_capacity(num_parties);
        for (session, x_) in sessions.into_iter().zip(x_shares.iter().cloned()) {
            let proof = session.challenge(x_, challenge.to_owned()).unwrap();
            proofs.push(proof);
        }

        // 4) Client combines all proofs
        let proof = challenge.combine_proofs(&proofs).unwrap();

        // Verify the result and the proof
        let d = Projective::generator().into_affine();
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
