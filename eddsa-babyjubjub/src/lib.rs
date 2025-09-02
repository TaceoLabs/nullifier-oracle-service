use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use num_bigint::BigUint;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

/// A private key for the EdDSA signature scheme.
#[derive(Debug, Clone, ZeroizeOnDrop, PartialEq, Eq, Hash)]
pub struct EdDSAPrivateKey(pub [u8; 32]);

impl EdDSAPrivateKey {
    /// Create a private key from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random private key using the given RNG.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hash the private key using Blake3 to derive the actual signing key.
    /// Low 32 bytes are used to derive the scalar signing key.
    /// High 32 bytes are used to derive the nonce.
    fn hash_blake(&self) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        let mut r = hasher.finalize_xof();
        let mut output = [0u8; 64]; // 512 bits to get no bias when doing mod reduction
        r.fill(&mut output);
        output
    }

    // panics if input is less than 32 bytes
    fn derive_sk(input: &[u8]) -> ScalarField {
        let sk_buf = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&input[0..32]);
            // prune buffer
            // sk = multiple of 8
            buf[0] &= 0xF8;
            // sk < r
            buf[31] &= 0x7F;
            // sk has highest bit set
            buf[31] |= 0x40;
            buf
        };
        ScalarField::from_le_bytes_mod_order(&sk_buf)
    }

    /// Derive the public key corresponding to this private key.
    pub fn public(&self) -> EdDSAPublicKey {
        let out = self.hash_blake();
        let sk = Self::derive_sk(&out);
        let pk = (Affine::generator() * sk).into_affine();
        EdDSAPublicKey { pk }
    }

    /// This function produces a nonce deterministically from the message and the secret key.
    ///
    /// This is a standard technique to avoid nonce reuse and to make the signature deterministic.
    fn deterministic_nonce(message: BaseField, sk: ScalarField) -> ScalarField {
        // We hash the private key and the message to produce the nonce r
        let mut hasher = blake3::Hasher::new();
        hasher.update(&sk.into_bigint().to_bytes_le());
        hasher.update(&message.into_bigint().to_bytes_le());
        let mut r = hasher.finalize_xof();
        let mut output = [0u8; 64]; // 512 bits to get no bias when doing mod reduction
        r.fill(&mut output);
        ScalarField::from_le_bytes_mod_order(&output)
    }

    /// Sign a message (a BaseField element) with the given secret key (a ScalarField element).
    ///
    /// The message should be hashed to a BaseField element if it is not encodable as one before signing.
    pub fn sign(&self, message: BaseField) -> EdDSASignature {
        let out = self.hash_blake();
        let sk = Self::derive_sk(&out);
        let nonce_secret = ScalarField::from_le_bytes_mod_order(&out[32..64]);

        let r = Self::deterministic_nonce(message, nonce_secret);
        let nonce_r = Affine::generator() * r;

        let pk = Affine::generator() * sk;
        let challenge = challenge_hash(message, nonce_r.into_affine(), pk.into_affine());
        let c = convert_base_to_scalar(challenge);
        let s = r + c * sk;

        EdDSASignature {
            r: nonce_r.into_affine(),
            s,
        }
    }
}

/// A public key for the EdDSA signature scheme over the BabyJubJubCurve.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdDSAPublicKey {
    pub pk: Affine,
}

impl EdDSAPublicKey {
    /// Verify the signature against the given message and public key.
    ///
    /// This verification function follows <https://eprint.iacr.org/2020/1244.pdf> to avoid common pitfalls.
    /// In particular, this uses a so-called "cofactored" verification, such that batched signature verification is possible.
    ///
    /// The only assumption is that both the public key and the nonce point R are canonical, i.e., their encoding is using valid field elements, which must be checked during deserialization.
    pub fn verify(&self, message: BaseField, signature: &EdDSASignature) -> bool {
        // 1. Reject the signature if s not in [0, L-1]
        // The following check is required to prevent malleability of the proofs by using different s, such as s + p, if s is given as a BaseField element.
        // In Rust this check is not required since self.s is a ScalarField element already, but we keep it to have the same implementation as in circom (where it is required).
        let s_biguint: BigUint = signature.s.into();
        if s_biguint >= ScalarField::MODULUS.into() {
            return false;
        }

        // 2. Reject the signature if the public key A is one of 8 small order points.
        // This boils down to the following checks.
        if [self.pk, signature.r]
            .iter()
            .any(|p| !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve())
        {
            return false;
        }
        if [self.pk, signature.r].iter().any(|p| p.is_zero()) {
            return false;
        }
        // 3. Reject the signature if A or R are non-canonical. We do not do this directly here, instead leaving this to the rust type system which ensure that the field elements are canonical.
        // All deserialization routines need to ensure that only canonical field elements are accepted.

        // 4. Compute the hash and reduce it mod the scalar field order L
        let challenge = challenge_hash(message, signature.r, self.pk);
        let c = convert_base_to_scalar(challenge);
        // 5. Accept if 8*(s*G) = 8*R + 8*(c*Pk)
        // Implemented by checking that 8(s*G - R - c*Pk) = 0, according to Section 4 of the above paper.
        let mut v = (Affine::generator() * signature.s) - signature.r - (self.pk * c);
        // multiply by the cofactor 8
        v.double_in_place();
        v.double_in_place();
        v.double_in_place();
        v.is_zero()
    }
}

/// An EdDSA signature on the Baby Jubjub curve, using Poseidon2 as the internal hash function for the Fiat-Shamir transform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdDSASignature {
    pub r: Affine,
    pub s: ScalarField,
}

// TODO maybe use a poseidon variant with t=8 here?
fn challenge_hash(message: BaseField, nonce_r: Affine, pk: Affine) -> BaseField {
    let poseidon2_4 = Poseidon2::<_, 4, 5>::default();
    let mut state = poseidon2_4.permutation(&[BaseField::zero(), nonce_r.x, nonce_r.y, pk.x]);
    state[1] += pk.y;
    state[2] += message;
    poseidon2_4.permutation(&state)[1]
}
// This is just a modular reduction. We show in the docs why this does not introduce a bias when applied to a uniform element of the base field.
pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use poseidon2::field_from_hex_string;

    use super::*;

    fn test(sk: [u8; 32], message: BaseField, rng: &mut impl rand::Rng) {
        let sk = EdDSAPrivateKey::from_bytes(sk);
        let pk = sk.public();
        // println!("pk=({:?}n, {:?}n)", pk.x, pk.y);

        let signature = sk.sign(message);
        assert!(
            pk.verify(message, &signature),
            "valid signature should verify"
        );
        // println!(
        //     "signature: s={:?}n, r=({:?}n, {:?}n)",
        //     signature.s, signature.r.x, signature.r.y,
        // );
        // println!("message={:?}", message);

        let message_ = BaseField::rand(rng);
        assert!(
            !pk.verify(message_, &signature),
            "invalid signature should not verify"
        );
        let sk_ = ScalarField::rand(rng);
        let pk_ = (Affine::generator() * sk_).into_affine();
        let pk_ = EdDSAPublicKey { pk: pk_ };
        assert!(
            !pk_.verify(message, &signature),
            "invalid signature should not verify"
        );
    }

    #[test]
    fn test_eddsa_rng() {
        let mut rng = rand::thread_rng();
        let sk = rng.r#gen();
        let message = BaseField::rand(&mut rng);
        test(sk, message, &mut rng);
    }

    #[test]
    fn test_eddsa_kat0() {
        let mut rng = rand::thread_rng();
        let sk = b"11e822de29de9aef648b12049368633f";
        let message = field_from_hex_string::<BaseField>(
            "0x6e94c93c5fc8c67e9f18200f4f963aa73fe45071d441362d17ede7e84fa0dd9",
        )
        .unwrap();
        test(*sk, message, &mut rng);
    }

    #[test]
    fn test_eddsa_kat1() {
        let mut rng = rand::thread_rng();
        let sk = b"1cc01b8ddd6851915a42e0cfc6b7088c";
        let message = field_from_hex_string::<BaseField>(
            "0x671e7802b9c4f1165955b9477a378bf30fd5723fddf7e727934bf2a7c2f3265",
        )
        .unwrap();
        test(*sk, message, &mut rng);
    }
}
