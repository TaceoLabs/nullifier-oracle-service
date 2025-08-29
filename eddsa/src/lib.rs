use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use poseidon2::Poseidon2;

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Projective = ark_babyjubjub::EdwardsProjective;
type Affine = ark_babyjubjub::EdwardsAffine;

pub struct Signature {
    pub(crate) r: Affine,
    pub(crate) s: ScalarField,
}

// This is just a modular reduction. We show in the docs why this does not introduce a bias when applied to a uniform element of the base field.
pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

pub fn sign(sk: ScalarField, message: BaseField) -> Signature {
    // We hash the private key and the message to produce the nonce r
    let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
    let sk_ = BaseField::from(sk.into_bigint()); // Basefield is bigger than scalar field
    let r = poseidon2_3.permutation(&[BaseField::zero(), sk_, message])[1];

    let r_ = convert_base_to_scalar(r);
    let nonce_r = Projective::generator().into_affine() * r_;

    let pk = Projective::generator().into_affine() * sk;
    // TODO maybe use t=8 here? This is also not yet compatible with the circom implementation
    let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
    let mut state = poseidon2_4.permutation(&[BaseField::zero(), nonce_r.x, nonce_r.y, pk.x]);
    state[1] += pk.y;
    state[2] += message;
    let challenge = poseidon2_4.permutation(&state)[1];

    let c = convert_base_to_scalar(challenge);
    let s = r_ + c * sk;

    Signature {
        r: nonce_r.into_affine(),
        s,
    }
}
