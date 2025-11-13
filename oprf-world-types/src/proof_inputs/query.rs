use std::collections::HashMap;

use oprf_zk::proof_input::{self, ProofInput};
use ruint::aliases::U256;
use serde::Serialize;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

pub const MAX_PUBLIC_KEYS: usize = 7;

#[derive(Debug, Clone, Serialize)]
pub struct QueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine_sequence")]
    pub pk: [Affine; MAX_PUBLIC_KEYS],
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub pk_index: BaseField, // 0..6
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub s: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub r: Affine,
    // Credential Signature
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_type_id: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub cred_pk: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq_sequence")]
    pub cred_hashes: [BaseField; 2], // [claims_hash, associated_data_hash]
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_genesis_issued_at: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_expires_at: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub cred_s: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub cred_r: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub current_time_stamp: BaseField,
    // Merkle proof
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub merkle_root: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub depth: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub mt_index: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq_sequence")]
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub beta: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub rp_id: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub action: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub nonce: BaseField,
}

impl<const MAX_DEPTH: usize> ProofInput for QueryProofInput<MAX_DEPTH> {
    fn prepare_input(&self) -> HashMap<String, Vec<U256>> {
        let mut map = HashMap::new();
        map.insert(
            "pk".to_owned(),
            proof_input::affine_seq_to_u256_vec(&self.pk),
        );
        map.insert(
            "pk_index".to_owned(),
            proof_input::fq_to_u256_vec(self.pk_index),
        );
        map.insert("s".to_owned(), proof_input::fr_to_u256_vec(self.s));
        map.insert("r".to_owned(), proof_input::affine_to_u256_vec(self.r));
        map.insert(
            "cred_type_id".to_owned(),
            proof_input::fq_to_u256_vec(self.cred_type_id),
        );
        map.insert(
            "cred_pk".to_owned(),
            proof_input::affine_to_u256_vec(self.cred_pk),
        );
        map.insert(
            "cred_hashes".to_owned(),
            proof_input::fq_seq_to_u256_vec(&self.cred_hashes),
        );
        map.insert(
            "cred_genesis_issued_at".to_owned(),
            proof_input::fq_to_u256_vec(self.cred_genesis_issued_at),
        );
        map.insert(
            "cred_expires_at".to_owned(),
            proof_input::fq_to_u256_vec(self.cred_expires_at),
        );
        map.insert(
            "cred_s".to_owned(),
            proof_input::fr_to_u256_vec(self.cred_s),
        );
        map.insert(
            "cred_r".to_owned(),
            proof_input::affine_to_u256_vec(self.cred_r),
        );
        map.insert(
            "current_time_stamp".to_owned(),
            proof_input::fq_to_u256_vec(self.current_time_stamp),
        );
        map.insert(
            "merkle_root".to_owned(),
            proof_input::fq_to_u256_vec(self.merkle_root),
        );
        map.insert("depth".to_owned(), proof_input::fq_to_u256_vec(self.depth));
        map.insert(
            "mt_index".to_owned(),
            proof_input::fq_to_u256_vec(self.mt_index),
        );
        map.insert(
            "siblings".to_owned(),
            proof_input::fq_seq_to_u256_vec(&self.siblings),
        );
        map.insert("beta".to_owned(), proof_input::fr_to_u256_vec(self.beta));
        map.insert("rp_id".to_owned(), proof_input::fq_to_u256_vec(self.rp_id));
        map.insert(
            "action".to_owned(),
            proof_input::fq_to_u256_vec(self.action),
        );
        map.insert("nonce".to_owned(), proof_input::fq_to_u256_vec(self.nonce));
        map
    }
}
