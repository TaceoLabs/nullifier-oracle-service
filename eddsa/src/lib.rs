use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use num_bigint::BigUint;
use poseidon2::Poseidon2;

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Projective = ark_babyjubjub::EdwardsProjective;
type Affine = ark_babyjubjub::EdwardsAffine;

pub struct EdDSASignature {
    pub(crate) r: Affine,
    pub(crate) s: ScalarField,
}

impl EdDSASignature {
    // This is just a modular reduction. We show in the docs why this does not introduce a bias when applied to a uniform element of the base field.
    pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
        let bytes = f.into_bigint().to_bytes_le();
        ScalarField::from_le_bytes_mod_order(&bytes)
    }

    pub fn sign(message: BaseField, sk: ScalarField) -> Self {
        // We hash the private key and the message to produce the nonce r
        // TODO this could be any hash function
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let sk_ = BaseField::from(sk.into_bigint()); // Basefield is bigger than scalar field
        let r = poseidon2_3.permutation(&[BaseField::zero(), sk_, message])[1];

        let r_ = Self::convert_base_to_scalar(r);
        let nonce_r = Projective::generator().into_affine() * r_;

        let pk = Projective::generator().into_affine() * sk;
        let challenge = Self::challenge_hash(message, nonce_r.into_affine(), pk.into_affine());
        let c = Self::convert_base_to_scalar(challenge);
        let c = c.double().double().double(); // multiply by 8
        let s = r_ + c * sk;

        Self {
            r: nonce_r.into_affine(),
            s,
        }
    }

    pub fn verify(&self, message: BaseField, pk: Affine) -> bool {
        if [pk, self.r]
            .iter()
            .any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
        {
            return false;
        }
        if [pk, self.r].iter().any(|p| p.is_zero()) {
            return false;
        }

        // The following check is required to prevent malleability of the proofs by using different s, such as s + p, if s is given as a BaseField element.
        // TODO since self.s is a ScalarField element, this check is not needed. Remove?
        let s_biguint: BigUint = self.s.into();
        if s_biguint >= ScalarField::MODULUS.into() {
            return false;
        }

        let challenge = Self::challenge_hash(message, self.r, pk);
        let c = Self::convert_base_to_scalar(challenge);
        let c = c.double().double().double(); // multiply by 8
        let lhs = Projective::generator() * self.s;
        let rhs = self.r + pk * c;
        lhs == rhs
    }

    // TODO maybe use t=8 here?
    fn challenge_hash(message: BaseField, nonce_r: Affine, pk: Affine) -> BaseField {
        let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
        let mut state = poseidon2_4.permutation(&[BaseField::zero(), nonce_r.x, nonce_r.y, pk.x]);
        state[1] += pk.y;
        state[2] += message;
        poseidon2_4.permutation(&state)[1]
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use poseidon2::field_from_hex_string;

    use super::*;

    fn test(sk: ScalarField, message: BaseField, rng: &mut impl rand::Rng) {
        let pk = (Affine::generator() * sk).into_affine();
        // println!("pk=({:?}n, {:?}n)", pk.x, pk.y);

        let signature = EdDSASignature::sign(message, sk);
        assert!(
            signature.verify(message, pk),
            "valid signature should verify"
        );
        // println!(
        //     "signature: s={:?}n, r=({:?}n, {:?}n)",
        //     signature.s, signature.r.x, signature.r.y,
        // );
        // println!("message={:?}", message);

        let message_ = BaseField::rand(rng);
        assert!(
            !signature.verify(message_, pk),
            "invalid signature should not verify"
        );
        let sk_ = ScalarField::rand(rng);
        let pk_ = (Affine::generator() * sk_).into_affine();
        assert!(
            !signature.verify(message, pk_),
            "invalid signature should not verify"
        );
    }

    #[test]
    fn test_eddsa_rng() {
        let mut rng = rand::thread_rng();
        let sk = ScalarField::rand(&mut rng);
        let message = BaseField::rand(&mut rng);
        test(sk, message, &mut rng);
    }

    #[test]
    fn test_eddsa_kat0() {
        let mut rng = rand::thread_rng();
        let sk = field_from_hex_string::<ScalarField>(
            "0x11e822de29de9aef648b12049368633f4601bb1b7ed47e4e0b945fb31466998c",
        )
        .unwrap();
        let message = field_from_hex_string::<BaseField>(
            "0x6e94c93c5fc8c67e9f18200f4f963aa73fe45071d441362d17ede7e84fa0dd9",
        )
        .unwrap();
        test(sk, message, &mut rng);
    }

    #[test]
    fn test_eddsa_kat1() {
        let mut rng = rand::thread_rng();
        let sk = field_from_hex_string::<ScalarField>(
            "0x1cc01b8ddd6851915a42e0cfc6b7088c4b660420cb103c96353d983ead661a5",
        )
        .unwrap();
        let message = field_from_hex_string::<BaseField>(
            "0x671e7802b9c4f1165955b9477a378bf30fd5723fddf7e727934bf2a7c2f3265",
        )
        .unwrap();
        test(sk, message, &mut rng);
    }
}
