use std::sync::Arc;

use ark_bn254::Bn254;
use ark_serde_compat::groth16::Groth16Proof;
use groth16::{ConstraintMatrices, ProvingKey};
use oprf_client::{CredentialsSignature, MerkleMembership, OprfQuery, OprfSession};

use oprf_types::crypto::UserPublicKeyBatch;
use rand::{CryptoRng, Rng};

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

type Affine = ark_babyjubjub::EdwardsAffine;
type BaseField = ark_babyjubjub::Fq;

// TODO docs for fields
pub struct NullifierArgs {
    pub credential_signature: CredentialsSignature,
    pub merkle_membership: MerkleMembership,
    pub oprf_query: OprfQuery,
    pub rp_nullifier_key: Affine,
    pub sk: EdDSAPrivateKey,
    pub pks: UserPublicKeyBatch,
    pub pk_index: u64,
    pub signal_hash: BaseField,
    pub signature: k256::ecdsa::Signature,
    pub id_commitment_r: BaseField,
    pub degree: usize,
    pub query_pk: Arc<ProvingKey<Bn254>>,
    pub query_matrices: Arc<ConstraintMatrices<ark_bn254::Fr>>,
    pub nullifier_pk: Arc<ProvingKey<Bn254>>,
    pub nullifier_matrices: Arc<ConstraintMatrices<ark_bn254::Fr>>,
}

pub async fn nullifier<R: Rng + CryptoRng>(
    oprf_services: &[String],
    args: NullifierArgs,
    rng: &mut R,
) -> eyre::Result<(Groth16Proof, Vec<BaseField>, BaseField)> {
    let NullifierArgs {
        rp_nullifier_key,
        sk,
        pks,
        pk_index,
        signal_hash,
        signature,
        id_commitment_r,
        degree,
        query_pk,
        query_matrices,
        nullifier_pk,
        nullifier_matrices,
        credential_signature,
        merkle_membership,
        oprf_query,
    } = args;

    let result = OprfSession::init(credential_signature, merkle_membership)?
        .sign_oprf_query(oprf_query, pks, pk_index, sk, rng)?
        .create_oprf_request(&query_pk, &query_matrices, signature, rng)?
        .init_sessions(oprf_services, degree + 1, rp_nullifier_key)
        .await?
        .challenge(
            signal_hash,
            id_commitment_r,
            &nullifier_pk,
            &nullifier_matrices,
            rng,
        )
        .await?;
    Ok(result)
}
