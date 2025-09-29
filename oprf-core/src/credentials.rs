use ark_ff::{PrimeField as _, Zero};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use poseidon2::Poseidon2;
use serde::{Deserialize, Serialize};

type BaseField = ark_babyjubjub::Fq;

pub struct UserCredentials {
    pub credential_type_id: BaseField,
    /// The index in the merkle tree
    pub user_id: u64,
    pub genesis_issued_at: u64,
    pub expires_at: u64,
    pub claims_hash: BaseField,
    pub associated_data_hash: BaseField,

    // private key
    pub cred_sk: EdDSAPrivateKey,
}

/// A batch  of end-user public keys
///
/// Stored in the Merkle-Tree at the Smart Contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicKeyBatch {
    /// Values of the the public key (always len 7)
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_user_key_batch")]
    pub values: [ark_babyjubjub::EdwardsAffine; 7],
}

pub struct UserKeys {
    pub keys_batch: UserPublicKeyBatch,
    pub sk: EdDSAPrivateKey,
    pub pk_index: u64,
}

impl UserCredentials {
    const CRED_DS: &[u8] = b"POSEIDON2+EDDSA-BJJ+DLBE-v1";

    // Returns the domain separator for the hashing of the credential message as a field element
    fn get_cred_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::CRED_DS)
    }

    pub fn pk(&self) -> EdDSAPublicKey {
        self.cred_sk.public()
    }

    pub fn credential_message(&self) -> BaseField {
        let poseidon2_8 = Poseidon2::<_, 8, 5>::default();
        let mut input = [
            Self::get_cred_ds(),
            self.credential_type_id,
            BaseField::from(self.user_id),
            self.genesis_issued_at.into(),
            self.expires_at.into(),
            self.claims_hash,
            self.associated_data_hash,
            BaseField::zero(),
        ];
        poseidon2_8.permutation_in_place(&mut input);
        input[1]
    }

    pub fn sign(&self) -> EdDSASignature {
        self.cred_sk.sign(self.credential_message())
    }
}
