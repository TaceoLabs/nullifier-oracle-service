use crate::{
    ddlog_equality::{
        DLogEqualityChallenge, DLogEqualityProofShare, PartialDLogEqualityCommitments,
    },
    dlog_equality::DLogEqualityProof,
    oprf::OPrfError,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Zero;

type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;
type Projective = ark_babyjubjub::EdwardsProjective;

// The Shamir version uses the same prover implementation as the additive version. The reason is that if each server samples the value k_i individually at random (instead of using the Shamir.rand() subroutine), then for each set of d servers, their k_i represent a valid random Shamir share. Since only d servers are ever required (e.g., we do not have a shared multiplication), we do not need all n random k_i to be on the same polynomial. Thus, we do not require an extra communication round to create shares of a random k.

impl DLogEqualityChallenge {
    /// The accumulating party (e.g., the verifier) combines the shares of d+1 parties and creates the challenge hash.
    pub fn combine_commitments_and_create_challenge_shamir(
        commitments: &[PartialDLogEqualityCommitments],
        lagrange: &[ScalarField], // Lagrange coefficients for each share
        a: Affine,                // Combined public key of the provers
        b: Affine,
    ) -> Result<(Affine, Self), OPrfError> {
        assert_eq!(
            commitments.len(),
            lagrange.len(),
            "Number of commitments must match number of Lagrange coefficients"
        );
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

        for (lambda, comm) in lagrange.iter().zip(commitments) {
            c += comm.c * lambda;
            r1 += comm.r1 * lambda;
            r2 += comm.r2 * lambda;
        }

        // Create the challenge hash
        let d = Projective::generator().into_affine();
        let c = c.into_affine();
        let r1 = r1.into_affine();
        let r2 = r2.into_affine();

        let e = crate::dlog_equality::challenge_hash(a, b, c, d, r1, r2);

        Ok((c, DLogEqualityChallenge { request_id, e }))
    }

    pub fn combine_proofs_shamir(
        &self,
        proofs: &[DLogEqualityProofShare],
        lagrange: &[ScalarField], // Lagrange coefficients for each share
    ) -> Result<DLogEqualityProof, OPrfError> {
        assert_eq!(
            proofs.len(),
            lagrange.len(),
            "Number of commitments must match number of Lagrange coefficients"
        );
        let request_id = self.request_id;
        if proofs.iter().any(|p| p.request_id != request_id) {
            return Err(OPrfError::RequestIdMismatch);
        }

        let mut s = ScalarField::zero();
        for (lambda, proof) in lagrange.iter().zip(proofs) {
            s += proof.s * *lambda;
        }

        Ok(DLogEqualityProof { e: self.e, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddlog_equality::DlogEqualitySession;
    use ark_ff::{PrimeField, UniformRand};
    use rand::{Rng, seq::IteratorRandom};
    use uuid::Uuid;

    /// Evaluate the poly at the given x
    fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
        debug_assert!(!poly.is_empty());
        let mut iter = poly.iter().rev();
        let mut eval = iter.next().unwrap().to_owned();
        for coeff in iter {
            eval *= x;
            eval += coeff;
        }
        eval
    }

    /// Share
    fn share<F: PrimeField, R: Rng>(
        secret: F,
        num_shares: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<F> {
        let mut shares = Vec::with_capacity(num_shares);
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(secret);
        for _ in 0..degree {
            coeffs.push(F::rand(rng));
        }
        for i in 1..=num_shares {
            let share = evaluate_poly(&coeffs, F::from(i as u64));
            shares.push(share);
        }
        shares
    }

    /// Compute the lagrange coeffs
    fn lagrange_from_coeff<F: PrimeField>(coeffs: &[usize]) -> Vec<F> {
        let num = coeffs.len();
        let mut res = Vec::with_capacity(num);
        for i in coeffs.iter() {
            let mut num = F::one();
            let mut den = F::one();
            let i_ = F::from(*i as u64);
            for j in coeffs.iter() {
                if i != j {
                    let j_ = F::from(*j as u64);
                    num *= j_;
                    den *= j_ - i_;
                }
            }
            let res_ = num * den.inverse().unwrap();
            res.push(res_);
        }
        res
    }

    /// Reconstruct the from its shares and lagrange coefficients.
    fn reconstruct<F: PrimeField>(shares: &[F], lagrange: &[F]) -> F {
        debug_assert_eq!(shares.len(), lagrange.len());
        let mut res = F::zero();
        for (s, l) in shares.iter().zip(lagrange.iter()) {
            res += *s * l
        }

        res
    }

    /// Reconstructs a curve point from its Shamir shares and lagrange coefficients.
    fn reconstruct_point<C: CurveGroup>(shares: &[C], lagrange: &[C::ScalarField]) -> C {
        debug_assert_eq!(shares.len(), lagrange.len());
        let mut res = C::zero();
        for (s, l) in shares.iter().zip(lagrange.iter()) {
            res += *s * l
        }

        res
    }

    #[expect(unused)]
    fn reconstruct_random_shares<F: PrimeField, R: Rng>(
        shares: &[F],
        degree: usize,
        rng: &mut R,
    ) -> F {
        let num_parties = shares.len();
        let parties = (1..=num_parties).choose_multiple(rng, degree + 1);
        let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
        let lagrange = lagrange_from_coeff(&parties);
        reconstruct(&shares, &lagrange)
    }

    fn reconstruct_random_pointshares<C: CurveGroup, R: Rng>(
        shares: &[C],
        degree: usize,
        rng: &mut R,
    ) -> C {
        let num_parties = shares.len();
        let parties = (1..=num_parties).choose_multiple(rng, degree + 1);
        let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
        let lagrange = lagrange_from_coeff(&parties);
        reconstruct_point(&shares, &lagrange)
    }

    fn test_distributed_dlog_equality(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        let x = ScalarField::rand(&mut rng);
        let x_shares = share(x, num_parties, degree, &mut rng);

        // Create public keys
        let public_key = (Projective::generator() * x).into_affine();
        let public_key_shares = x_shares
            .iter()
            .map(|x| (Projective::generator() * x))
            .collect::<Vec<_>>();
        let public_key_ = reconstruct_random_pointshares(&public_key_shares, degree, &mut rng);
        assert_eq!(public_key, public_key_);

        // Crete session and choose the used set of parties
        let request_id = Uuid::new_v4();
        let b = Affine::rand(&mut rng);
        let used_parties = (1..=num_parties).choose_multiple(&mut rng, degree + 1);
        let lagrange = lagrange_from_coeff(&used_parties);

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
        // Choose the commitments of the used parties
        let used_commitments = used_parties
            .iter()
            .map(|&i| commitments[i - 1].clone())
            .collect::<Vec<_>>();

        let (c, challenge) =
            DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
                &used_commitments,
                &lagrange,
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
        // Choose the proofs of the used parties
        let used_proofs = used_parties
            .iter()
            .map(|&i| proofs[i - 1].clone())
            .collect::<Vec<_>>();
        let proof = challenge
            .combine_proofs_shamir(&used_proofs, &lagrange)
            .unwrap();

        // Verify the result and the proof
        let d = Projective::generator().into_affine();
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
