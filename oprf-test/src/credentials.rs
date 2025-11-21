use ark_ff::{PrimeField as _, UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPrivateKey;
use oprf_world_types::{
    CredentialsSignature, UserKeyMaterial, UserPublicKeyBatch, proof_inputs::query::MAX_PUBLIC_KEYS,
};
use rand::{CryptoRng, Rng};

type BaseField = ark_babyjubjub::Fq;
const CRED_DS: &[u8] = b"POSEIDON2+EDDSA-BJJ";

pub fn random_user_keys<R: Rng + CryptoRng>(rng: &mut R) -> UserKeyMaterial {
    let sk = EdDSAPrivateKey::random(rng);
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let mut pks = UserPublicKeyBatch {
        values: rng.r#gen(),
    };
    pks.values[pk_index as usize] = sk.public().pk;
    UserKeyMaterial {
        pk_batch: pks,
        pk_index,
        sk,
    }
}

pub fn random_credential_signature<R: Rng + CryptoRng>(
    user_id: u64,
    current_time_stamp: u64,
    rng: &mut R,
) -> CredentialsSignature {
    let type_id = BaseField::rand(rng);
    let cred_hashes = [BaseField::rand(rng), BaseField::rand(rng)];
    let genesis_issued_at = rng.r#gen::<u64>();
    let expires_at = rng.gen_range(current_time_stamp + 1..=u64::MAX);

    let mut input = [
        BaseField::from_be_bytes_mod_order(CRED_DS),
        type_id,
        user_id.into(),
        genesis_issued_at.into(),
        expires_at.into(),
        cred_hashes[0],
        cred_hashes[1],
        BaseField::zero(),
    ];
    poseidon2::bn254::t8::permutation_in_place(&mut input);
    let sk = EdDSAPrivateKey::random(rng);

    CredentialsSignature {
        type_id,
        issuer: sk.public(),
        hashes: cred_hashes,
        signature: sk.sign(input[1]),
        genesis_issued_at,
        expires_at,
    }
}
