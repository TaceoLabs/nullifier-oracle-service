use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use rand::{CryptoRng, Rng};

pub struct DLogEqualityProof {
    e: ScalarField,
    s: ScalarField,
}

type ScalarField = ark_ed_on_bn254::Fr;
type BaseField = ark_ed_on_bn254::Fq;
type Affine = ark_ed_on_bn254::EdwardsAffine;
type Projective = ark_ed_on_bn254::EdwardsProjective;

impl DLogEqualityProof {
    pub fn proof(b: Affine, x: ScalarField, rng: &mut (impl CryptoRng + Rng)) -> Self {
        let k = ScalarField::rand(rng);
        let r1 = (Projective::generator() * k).into_affine();
        let r2 = (b * k).into_affine();
        let a = (Projective::generator() * x).into_affine();
        let c = (b * x).into_affine();
        let d = Projective::generator().into_affine();
        let e = challenge_hash(a, b, c, d, r1, r2);
        let e = convert_base_to_scalar(e);
        let s = k + e * x;
        DLogEqualityProof { e, s }
    }

    pub fn verify(&self, a: Affine, b: Affine, c: Affine, d: Affine) -> bool {
        if [a, b, c, d].iter().any(|p| p.is_zero()) {
            return false;
        }
        let r_1 = Projective::generator() * self.s - a * self.e;
        if r_1.is_zero() {
            return false;
        }
        let r_2 = b * self.s - c * self.e;
        if r_2.is_zero() {
            return false;
        }
        let e = challenge_hash(a, b, c, d, r_1.into_affine(), r_2.into_affine());
        let e = convert_base_to_scalar(e);
        e == self.e
    }
}

fn challenge_hash(a: Affine, b: Affine, c: Affine, d: Affine, r1: Affine, r2: Affine) -> BaseField {
    // TODO: Poseidon with statesize of at least 6*2?
    let hash_input = [
        BaseField::zero(),
        a.x,
        a.y,
        b.x, //b.y, c.x, c.y, d.x, d.y, r1.x, r1.y, r2.x, r2.y,
    ];
    let poseidon = poseidon2::Poseidon2::new(&poseidon2::POSEIDON2_BN254_PARAMS_4);
    let mut state = poseidon.permutation(&hash_input);
    state[1] += b.y;
    state[2] += c.x;
    state[3] += c.y;
    let mut state = poseidon.permutation(&state);
    state[1] += d.x;
    state[2] += d.y;
    state[3] += r1.x;
    let mut state = poseidon.permutation(&state);
    state[1] += r1.y;
    state[2] += r2.x;
    state[3] += r2.y;
    let state = poseidon.permutation(&state);

    state[1] // output first state element as hash output
}

fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_dlog_equality() {
        let mut rng = rand::thread_rng();
        let x = ScalarField::rand(&mut rng);
        let d = Projective::generator().into_affine();
        let a = (d * x).into_affine();
        let b = Affine::rand(&mut rng);
        let c = (b * x).into_affine();

        let proof = DLogEqualityProof::proof(b, x, &mut rng);
        assert!(proof.verify(a, b, c, d), "valid proof should verify");
        let b2 = Affine::rand(&mut rng);
        let invalid_proof = DLogEqualityProof::proof(b2, x, &mut rng);
        assert!(
            !invalid_proof.verify(a, b, c, d),
            "invalid proof should not verify"
        );
    }
}
