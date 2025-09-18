use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCommitment {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub comm_share: ark_babyjubjub::EdwardsAffine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub comm_coeffs: ark_babyjubjub::Fq,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpSecretGenCiphertexts(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_dict_g1",
        deserialize_with = "ark_serde_compat::deserialize_dict_g1"
    )]
    HashMap<ark_babyjubjub::EdwardsAffine, RpSecretGenCiphertext>,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCiphertext {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    nonce: ark_babyjubjub::Fq,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    cipher: ark_babyjubjub::Fq,
}

impl RpSecretGenCiphertexts {
    pub fn get_cipher_text(
        &self,
        filter: ark_babyjubjub::EdwardsAffine,
    ) -> Option<RpSecretGenCiphertext> {
        self.0.get(&filter).cloned()
    }
}
