use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use oprf_types::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch, crypto::UserPublicKeyBatch};

#[derive(Clone)]
pub struct CredentialsSignature {
    pub type_id: ark_babyjubjub::Fq,
    pub issuer: EdDSAPublicKey,
    pub hashes: [ark_babyjubjub::Fq; 2], // [claims_hash, associated_data_hash]
    pub signature: EdDSASignature,
    pub genesis_issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct MerkleMembership {
    pub epoch: MerkleEpoch,
    pub root: MerkleRoot,
    pub depth: u64,
    pub mt_index: u64,
    pub siblings: Vec<ark_babyjubjub::Fq>,
}

#[derive(Clone)]
pub struct OprfQuery {
    pub rp_id: RpId,
    pub share_epoch: ShareEpoch,
    pub action: ark_babyjubjub::Fq,
    pub nonce: ark_babyjubjub::Fq,
    pub current_time_stamp: u64,
    pub nonce_signature: k256::ecdsa::Signature,
}

#[derive(Clone)]
pub struct UserKeyMaterial {
    pub pk_batch: UserPublicKeyBatch,
    pub pk_index: u64, // 0..6
    pub sk: EdDSAPrivateKey,
}

impl UserKeyMaterial {
    pub fn public_key(&self) -> ark_babyjubjub::EdwardsAffine {
        self.pk_batch.values[self.pk_index as usize]
    }
}
