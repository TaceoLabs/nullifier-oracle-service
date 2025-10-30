use crate::ddlog_equality::{
    DLogEqualityCommitments, DLogEqualityProofShare, DLogEqualitySession,
    PartialDLogEqualityCommitments, combine_twononce_randomness,
};
use ark_ec::CurveGroup;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Zero;
use uuid::Uuid;

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

// The Shamir version uses the same prover implementation as the additive version. The reason is that if each server samples the value k_i individually at random (instead of using the Shamir.rand() subroutine), then for each set of d servers, their k_i represent a valid random Shamir share. Since only d servers are ever required (e.g., we do not have a shared multiplication), we do not need all n random k_i to be on the same polynomial. Thus, we do not require an extra communication round to create shares of a random k.

impl DLogEqualityCommitments {
    /// The accumulating party (e.g., the verifier) combines the shares of d+1 parties.
    ///
    /// # Panics
    /// Panics if the number of commitments does not match the number of Lagrange coefficients, i.e. `commitments.len() != lagrange.len()`.
    pub fn combine_commitments_shamir(
        commitments: &[PartialDLogEqualityCommitments],
        contributing_parties: Vec<u16>,
    ) -> Self {
        let lagrange = crate::shamir::lagrange_from_coeff(&contributing_parties);
        assert_eq!(
            commitments.len(),
            lagrange.len(),
            "Number of commitments must match number of Lagrange coefficients"
        );

        let c = Projective::msm_unchecked(
            &commitments.iter().map(|comm| comm.c).collect::<Vec<_>>(),
            &lagrange,
        );
        let mut d1 = Projective::zero();
        let mut d2 = Projective::zero();
        let mut e1 = Projective::zero();
        let mut e2 = Projective::zero();

        for comm in commitments.iter() {
            d1 += comm.d1;
            d2 += comm.d2;
            e1 += comm.e1;
            e2 += comm.e2;
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
}

impl DLogEqualitySession {
    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    pub fn challenge_shamir(
        self,
        session_id: Uuid,
        x_share: ScalarField,
        a: Affine,
        challenge_input: DLogEqualityCommitments,
        lagrange_coefficient: ScalarField,
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
            &challenge_input.contributing_parties,
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
            s: self.d + b * self.e + lagrange_coefficient * e_ * x_share,
        }
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
            .map(|x| Affine::generator() * x)
            .collect::<Vec<_>>();
        let public_key_ =
            shamir::reconstruct_random_pointshares(&public_key_shares, degree, &mut rng);
        assert_eq!(public_key, public_key_);

        // Crete session and choose the used set of parties
        let session_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);
        let used_parties = (1..=num_parties as u16).choose_multiple(&mut rng, degree + 1);

        // 1) Client requests commitments from all servers
        let mut sessions = Vec::with_capacity(num_parties);
        let mut commitments = Vec::with_capacity(num_parties);
        for x_ in x_shares.iter().cloned() {
            let (session, comm) = DLogEqualitySession::partial_commitments(b, x_, &mut rng);
            sessions.push(Some(session));
            commitments.push(comm);
        }

        // 2) Client accumulates commitments and creates challenge
        // Choose the commitments of the used parties
        let used_commitments = used_parties
            .iter()
            .map(|&i| commitments[i as usize - 1].clone())
            .collect::<Vec<_>>();

        let challenge = DLogEqualityCommitments::combine_commitments_shamir(
            &used_commitments,
            used_parties.clone(),
        );
        let c = challenge.blinded_response();

        // 3) Client challenges used servers (not needed, could only challenge used parties)
        let mut used_proofs = Vec::with_capacity(num_parties);

        for server_idx in &used_parties {
            // we just use an option here in tests to be able to move out of the vector since the session is consumed
            let session = sessions[*server_idx as usize - 1]
                .take()
                .expect("have not used this session before");
            let x_ = x_shares[*server_idx as usize - 1];
            let proof = session.challenge_shamir(
                session_id,
                x_,
                public_key,
                challenge.clone(),
                shamir::single_lagrange_from_coeff(*server_idx, &used_parties),
            );
            used_proofs.push(proof);
        }

        // 4) Client combines received proof shares
        let proof =
            challenge.combine_proofs(session_id, &used_parties, &used_proofs, public_key, b);

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
