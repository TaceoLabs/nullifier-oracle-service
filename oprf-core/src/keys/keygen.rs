use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use itertools::izip;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};

use crate::shamir;

type ScalarField = ark_babyjubjub::Fr;
type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

pub struct KeyGenPoly {
    poly: Vec<ScalarField>,
    comm_share: Affine,
    comm_coeffs: BaseField,
}

impl KeyGenPoly {
    // Absorb 2, squeeze 1,  domainsep = 0x4142
    // [0x80000002, 0x00000001, 0x4142]
    const T1_DS: u128 = 0x80000002000000014142;
    const COEFF_DS: &[u8] = b"KeyGenPolyCoeff";
    const SHARE_DS: &[u8] = b"KeyGenPolyShare";

    // Returns the used domain separator as a field element for the encryption
    fn get_t1_ds() -> BaseField {
        BaseField::from(Self::T1_DS)
    }

    // Returns the used domain separator as a field element for the commitment to the coefficients
    fn get_coeff_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::COEFF_DS)
    }

    // Returns the used domain separator as a field element for the commitment to the share
    fn get_share_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::SHARE_DS)
    }

    fn interpret_scalarfield_as_basefield(s: ScalarField) -> BaseField {
        let s_bigint = s.into_bigint();
        BaseField::from_bigint(s_bigint).expect("scalar field element fits in base field")
    }

    fn basefield_as_scalarfield_if_fits(s: BaseField) -> std::io::Result<ScalarField> {
        let s_bigint = s.into_bigint();
        ScalarField::from_bigint(s_bigint).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "base field element does not fit in scalar field",
        ))
    }

    pub fn keygen<R: Rng + CryptoRng>(rng: &mut R, degree: usize) -> Self {
        let poly = (0..degree + 1)
            .map(|_| ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let comm_share = Affine::generator() * poly[0];

        // Sponge mode for hashing
        let poseidon2_4 = Poseidon2::<BaseField, 4, 5>::default();
        let mut state = [BaseField::zero(); 4];
        state[0] = Self::get_coeff_ds(); // domain separator in capacity
        for coeffs_ in poly[1..].chunks(3) {
            for (s, c) in izip!(state.iter_mut().skip(1), coeffs_) {
                *s += Self::interpret_scalarfield_as_basefield(*c);
            }
            poseidon2_4.permutation_in_place(&mut state);
        }
        let comm_coeffs = state[1];

        Self {
            poly,
            comm_share: comm_share.into_affine(),
            comm_coeffs,
        }
    }

    fn dh_key_derivation(my_sk: ScalarField, their_pk: Affine) -> BaseField {
        (their_pk * my_sk).into_affine().x
    }

    fn sym_encrypt(key: BaseField, msg: ScalarField, nonce: BaseField) -> BaseField {
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let ks = poseidon2_3.permutation(&[Self::get_t1_ds(), key, nonce]);
        ks[1] + Self::interpret_scalarfield_as_basefield(msg)
    }

    fn sym_decrypt(
        key: BaseField,
        ciphertext: BaseField,
        nonce: BaseField,
    ) -> std::io::Result<ScalarField> {
        let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
        let ks = poseidon2_3.permutation(&[Self::get_t1_ds(), key, nonce]);
        let msg = ciphertext - ks[1];
        Self::basefield_as_scalarfield_if_fits(msg)
    }

    pub fn decrypt_share(
        my_sk: ScalarField,
        their_pk: Affine,
        ciphertext: BaseField,
        nonce: BaseField,
    ) -> std::io::Result<ScalarField> {
        let symm_key = Self::dh_key_derivation(my_sk, their_pk);
        Self::sym_decrypt(symm_key, ciphertext, nonce)
    }

    // Party ID from 0..n-1
    // Returns the commitment to the share and the encrypted share
    pub fn gen_share(
        &self,
        id: usize,
        my_sk: ScalarField,
        their_pk: Affine,
        nonce: BaseField,
    ) -> (BaseField, BaseField) {
        let index = ScalarField::from((id + 1) as u64);
        let share = shamir::evaluate_poly(&self.poly, index);

        let symm_key = Self::dh_key_derivation(my_sk, their_pk);
        let ciphertext = Self::sym_encrypt(symm_key, share, nonce);

        let poseidon2_2 = Poseidon2::<_, 2, 5>::default();
        // The share is random, so no need for randomness here
        let commitment = poseidon2_2.permutation(&[
            Self::get_share_ds(), // domain separator in capacity
            Self::interpret_scalarfield_as_basefield(share),
        ])[1];

        (commitment, ciphertext)
    }

    pub fn accumulate_shares(shares: &[ScalarField]) -> ScalarField {
        shares.iter().fold(ScalarField::zero(), |acc, x| acc + x)
    }

    pub fn accumulate_pks(pks: &[Affine]) -> Affine {
        pks.iter()
            .fold(ark_babyjubjub::EdwardsProjective::zero(), |acc, x| acc + *x)
            .into_affine()
    }

    pub fn degree(&self) -> usize {
        self.poly.len() - 1
    }

    pub fn get_pk_share(&self) -> Affine {
        self.comm_share
    }

    pub fn get_coeff_commitment(&self) -> BaseField {
        self.comm_coeffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_distributed_keygen(num_parties: usize, degree: usize) {
        let mut rng = rand::thread_rng();

        // Init party secret keys and public keys
        let party_sks = (0..num_parties)
            .map(|_| ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let party_pks = party_sks
            .iter()
            .map(|x| (Affine::generator() * *x).into_affine())
            .collect::<Vec<_>>();

        // 1. Each party commits to a random polynomial
        let party_polys = (0..num_parties)
            .map(|_| KeyGenPoly::keygen(&mut rng, degree))
            .collect::<Vec<_>>();

        // The desired result based on the created polys
        let should_sk = party_polys
            .iter()
            .fold(ScalarField::zero(), |acc, x| acc + x.poly[0]);
        let should_pk = Affine::generator() * should_sk;

        // pk from commitments
        let pks = party_polys
            .iter()
            .map(|x| x.get_pk_share())
            .collect::<Vec<_>>();
        let pk_from_comm = KeyGenPoly::accumulate_pks(&pks);
        assert_eq!(should_pk, pk_from_comm);

        // 2. Each party creates all shares
        let mut encryption_nonces = Vec::with_capacity(num_parties);
        let mut party_ciphers = Vec::with_capacity(num_parties);
        for (poly, my_sk) in izip!(party_polys, party_sks.iter()) {
            let mut nonces = Vec::with_capacity(num_parties);
            let mut cipher = Vec::with_capacity(num_parties);
            for (i, their_pk) in party_pks.iter().enumerate() {
                let nonce = BaseField::rand(&mut rng);
                let (_, ciphertext) = poly.gen_share(i, *my_sk, *their_pk, nonce);
                nonces.push(nonce);
                cipher.push(ciphertext);
            }
            encryption_nonces.push(nonces);
            party_ciphers.push(cipher);
        }

        // 3. Each party decrypts their shares
        let mut result_shares = Vec::with_capacity(num_parties);
        for (i, my_sk) in party_sks.iter().enumerate() {
            let mut my_shares = Vec::with_capacity(num_parties);
            for (cipher, nonce, their_pk) in izip!(
                party_ciphers.iter(),
                encryption_nonces.iter(),
                party_pks.iter()
            ) {
                let share = KeyGenPoly::decrypt_share(*my_sk, *their_pk, cipher[i], nonce[i])
                    .expect("decryption should work");
                my_shares.push(share);
            }
            let my_share = KeyGenPoly::accumulate_shares(&my_shares);
            result_shares.push(my_share);
        }

        // Check if the correct secret share is obtained
        let sk_from_shares = shamir::reconstruct_random_shares(&result_shares, degree, &mut rng);
        assert_eq!(should_sk, sk_from_shares);

        // Check if the correct public key is obtained
        let pk_shares = result_shares
            .iter()
            .map(|x| Affine::generator() * *x)
            .collect::<Vec<_>>();
        let pk_from_shares = shamir::reconstruct_random_pointshares(&pk_shares, degree, &mut rng);
        assert_eq!(should_pk, pk_from_shares);
    }

    #[test]
    fn test_distributed_keygen_3_1() {
        test_distributed_keygen(3, 1);
    }

    #[test]
    fn test_distributed_keygen_31_15() {
        test_distributed_keygen(31, 15);
    }
}
