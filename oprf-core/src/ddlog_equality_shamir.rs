use crate::{
    ddlog_equality::{
        DLogEqualityChallenge, DLogEqualityProofShare, PartialDLogEqualityCommitments,
    },
    dlog_equality::DLogEqualityProof,
};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::Zero;

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

// The Shamir version uses the same prover implementation as the additive version. The reason is that if each server samples the value k_i individually at random (instead of using the Shamir.rand() subroutine), then for each set of d servers, their k_i represent a valid random Shamir share. Since only d servers are ever required (e.g., we do not have a shared multiplication), we do not need all n random k_i to be on the same polynomial. Thus, we do not require an extra communication round to create shares of a random k.

impl DLogEqualityChallenge {
    /// The accumulating party (e.g., the verifier) combines the shares of d+1 parties and creates the challenge hash.
    ///
    /// # Panics
    /// Panics if the number of commitments does not match the number of Lagrange coefficients, i.e. `commitments.len() != lagrange.len()`.
    pub fn combine_commitments_and_create_challenge_shamir(
        commitments: &[PartialDLogEqualityCommitments],
        lagrange: &[ScalarField], // Lagrange coefficients for each share
        a: Affine,                // Combined public key of the provers
        b: Affine,
    ) -> (Affine, Self) {
        assert_eq!(
            commitments.len(),
            lagrange.len(),
            "Number of commitments must match number of Lagrange coefficients"
        );

        let mut c = Projective::zero();
        let mut r1 = Projective::zero();
        let mut r2 = Projective::zero();

        for (lambda, comm) in lagrange.iter().zip(commitments) {
            c += comm.c * lambda;
            r1 += comm.r1 * lambda;
            r2 += comm.r2 * lambda;
        }

        // Create the challenge hash
        let d = Affine::generator();
        let c = c.into_affine();
        let r1 = r1.into_affine();
        let r2 = r2.into_affine();

        let e = crate::dlog_equality::challenge_hash(a, b, c, d, r1, r2);

        (c, DLogEqualityChallenge { e })
    }

    /// Combines the proof shares of d+1 parties into a full proof.
    ///
    /// # Panics
    /// Panics if the number of proofs does not match the number of Lagrange coefficients,
    /// i.e. `proofs.len() != lagrange.len()`.
    pub fn combine_proofs_shamir(
        self,
        proofs: &[DLogEqualityProofShare],
        lagrange: &[ScalarField], // Lagrange coefficients for each share
    ) -> DLogEqualityProof {
        assert_eq!(
            proofs.len(),
            lagrange.len(),
            "Number of commitments must match number of Lagrange coefficients"
        );

        let mut s = ScalarField::zero();
        for (lambda, proof) in lagrange.iter().zip(proofs) {
            s += proof.s * *lambda;
        }

        DLogEqualityProof { e: self.e, s }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ddlog_equality::DLogEqualitySession, shamir};
    use ark_ff::UniformRand;
    use rand::seq::IteratorRandom;

    fn test_distributed_dlog_equality(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        let x = ScalarField::rand(&mut rng);
        let x_shares = shamir::share(x, num_parties, degree, &mut rng);

        // Create public keys
        let public_key = (Affine::generator() * x).into_affine();
        let public_key_shares = x_shares
            .iter()
            .map(|x| (Affine::generator() * x))
            .collect::<Vec<_>>();
        let public_key_ =
            shamir::reconstruct_random_pointshares(&public_key_shares, degree, &mut rng);
        assert_eq!(public_key, public_key_);

        // Crete session and choose the used set of parties
        let b = Affine::rand(&mut rng);
        let used_parties = (1..=num_parties).choose_multiple(&mut rng, degree + 1);
        let lagrange = shamir::lagrange_from_coeff(&used_parties);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for x_ in x_shares.iter().cloned() {
            let (session, comm) = DLogEqualitySession::partial_commitments(b, x_, &mut rng);
            sessions.push(session);
            commitments.push(comm);
        }

        // 2) Client accumulates commitments and creates challenge
        // Choose the commitments of the used parties
        let used_commitments = used_parties
            .iter()
            .map(|&i| commitments[i - 1].clone())
            .collect::<Vec<_>>();

        let (c, challenge) = DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
            &used_commitments,
            &lagrange,
            public_key,
            b,
        );

        // 3) Client challenges all servers
        let mut proofs = Vec::with_capacity(num_parties);
        for (session, x_) in sessions.into_iter().zip(x_shares.iter().cloned()) {
            let proof = session.challenge(x_, challenge.to_owned());
            proofs.push(proof);
        }

        // 4) Client combines all proofs
        // Choose the proofs of the used parties
        let used_proofs = used_parties
            .iter()
            .map(|&i| proofs[i - 1].clone())
            .collect::<Vec<_>>();
        let proof = challenge.combine_proofs_shamir(&used_proofs, &lagrange);

        // Verify the result and the proof
        let d = Affine::generator();
        assert_eq!(c, b * x, "Result must be correct");
        assert!(
            proof.verify(public_key, b, c, d),
            "valid proof should verify"
        );
    }

    #[test]
    fn test_distributed_dlog_equality_shamir_3_1() {
        test_distributed_dlog_equality(3, 1);
    }

    #[test]
    fn test_distributed_dlog_equality_shamir_31_15() {
        test_distributed_dlog_equality(31, 15);
    }
}
