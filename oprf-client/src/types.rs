//! This module defines the core data structures of the OPRF client.
//!
//! Roughly:
//! - [`UserKeyMaterial`] holds the end-user’s signing keys
//! - [`OprfQuery`] the query object (containing the action of the user)
//! - [`MerkleMembership`] holds necessary information to prove membership in the Merkle tree
//! - [`CredentialsSignature`] represents a signed credential issued by world ecosystem

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use oprf_types::{MerkleRoot, RpId, ShareEpoch, TREE_DEPTH, crypto::UserPublicKeyBatch};

/// A credential object in the world ecosystem, together with its signature.  
/// See [Notion doc](https://www.notion.so/worldcoin/WID25-Credential-PCP-Structure-Lifecycle-2668614bdf8c805d9484d7dd8f68532b?source=copy_link#2698614bdf8c808f83ebe8889dad0af6) for details.
///
/// The user must prove in a ZK proof that they hold a valid credential
/// and that it was signed by an authorized issuer.
#[derive(Clone)]
pub struct CredentialsSignature {
    /// Unique credential type ID. Not relevant for the OPRF service,
    /// but included in the signature.
    pub type_id: ark_babyjubjub::Fq,
    /// The `claims hash` + `associated data hash`.
    pub hashes: [ark_babyjubjub::Fq; 2], // [claims_hash, associated_data_hash]
    /// Timestamp of original issuance (unix secs).
    pub genesis_issued_at: u64,
    /// Expiration timestamp (unix secs).
    pub expires_at: u64,
    /// The issuer of the credential.  
    /// Currently this is a public input to the Groth16 proof.  
    /// In upcoming versions, the OPRF service will fetch the issuer’s
    /// public key from chain (or another trusted source).
    pub issuer: EdDSAPublicKey,
    /// The credential’s signature object.
    pub signature: EdDSASignature,
}

/// Artifacts required to compute the Merkle inclusion proof
/// for a user’s public key.
///
/// Each public key is tied to a leaf in a Merkle tree.
/// To prove validity, the user shows membership in the tree
/// with a sibling path up to the root.
#[derive(Clone)]
pub struct MerkleMembership {
    /// The actual Merkle root (not sent to the OPRF service, only used for computing the proof).
    pub root: MerkleRoot,
    /// The index of the user’s leaf in the Merkle tree.
    pub mt_index: u64,
    /// The sibling path up to the Merkle root.  
    pub siblings: [ark_babyjubjub::Fq; TREE_DEPTH],
}

/// The basic request a client sends to the OPRF service.
///
/// It contains the relying party’s ID, the share epoch, the action
/// the user wants to compute a nullifier for, and a fresh nonce.
/// The RP signs `(nonce || timestamp)` (both in little-endian byte encoding)
/// to prevent replay. That signature is included here.
#[derive(Clone)]
pub struct OprfQuery {
    /// The ID of the RP that issued the nonce.
    pub rp_id: RpId,
    /// The epoch of the DLog share (currently always `0`).
    pub share_epoch: ShareEpoch,
    /// The action the user wants to compute a nullifier for.
    pub action: ark_babyjubjub::Fq,
    /// The nonce obtained from the RP.
    pub nonce: ark_babyjubjub::Fq,
    /// The timestamp obtained from the RP.
    pub current_time_stamp: u64,
    /// The RP's signature over `(nonce || timestamp)`.
    pub nonce_signature: k256::ecdsa::Signature,
}

/// Key material for the end-user.
///
/// Each user manages a batch of public keys but only one active
/// secret key. The `pk_index` selects which key in the batch
/// corresponds to the private key.
///
/// **Note**: Callers must ensure `pk_index < 7`.  
/// This implementation will panic if the index is out of bounds.
#[derive(Clone)]
pub struct UserKeyMaterial {
    /// A batch of public keys.
    pub pk_batch: UserPublicKeyBatch,
    /// The index in the batch that corresponds to the user’s public key.
    pub pk_index: u64, // 0..6
    /// The user’s private key.
    pub sk: EdDSAPrivateKey,
}

impl UserKeyMaterial {
    /// Returns the user’s currently active public key.
    ///
    /// # Panics
    ///
    /// Panics if `pk_index` is out of bounds relative to [`oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS`].
    pub fn public_key(&self) -> ark_babyjubjub::EdwardsAffine {
        self.pk_batch.values[self.pk_index as usize]
    }
}
