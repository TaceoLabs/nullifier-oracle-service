//! Types for communicating with the mock smart contract during staging tests.
//!
//! This module is only compiled when the `mock-chain-watcher` feature is enabled.  
//! It defines request/response types and event payloads exchanged with
//! the mock contract used in integration testing.

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    MerkleEpoch, MerkleRoot, RpId,
    chain::{ChainEvent, SecretGenFinalizeEvent, SecretGenRound1Event, SecretGenRound2Event},
    crypto::{
        PartyId, PeerPublicKey, PeerPublicKeyList, RpSecretGenCiphertext, UserPublicKeyBatch,
    },
};

impl UserPublicKeyBatch {
    /// Generates a random `UserPublicKey` with the provided source of randomness.
    pub fn random<R: Rng>(r: &mut R) -> Self {
        Self {
            values: std::array::from_fn(|_| r.r#gen()),
        }
    }
}

/// A MerklePath produced by the Smart Contract Mock.
///
/// Used for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePath {
    /// The index of the element in the tree
    pub index: u64,
    /// The siblings in the path
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base_sequence")]
    pub siblings: Vec<ark_babyjubjub::Fq>,
    /// The produced root
    pub root: MerkleRoot,
    /// The user-key batch (leaf)
    pub key_batch: UserPublicKeyBatch,
}

/// Represents an update of the Merkle root for a specific epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleRootUpdate {
    /// The merkle root
    pub hash: MerkleRoot,
    /// The epoch of the new root
    pub epoch: MerkleEpoch,
}

/// Request for `fetch_roots`.
///
/// Defines the amount of roots the OPRF-Service wants to load
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRootsRequest {
    /// The amount of roots to fetch (max value).
    pub amount: u32,
}

/// Requests for `get_party_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPartyIdRequest {
    /// The public key of the peer
    pub key: PeerPublicKey,
}

/// Response for `get_party_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPartyIdResponse {
    /// The party id
    pub party_id: PartyId,
}

/// Request for `is_valid_epoch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsValidEpochRequest {
    /// The epoch to check
    pub epoch: MerkleEpoch,
}

/// Request to add a new [`UserPublicKey`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPublicKeyRequest {
    /// The epoch to check
    pub public_key: UserPublicKeyBatch,
}

/// Response to for adding a [`UserPublicKey`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPublicKeyResponse {
    /// The epoch to check
    pub epoch: MerkleEpoch,
    /// The epoch to check
    pub path: MerklePath,
}

/// Request sent to read events for a given peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadEventsRequest {
    /// Party id of the peer whose events are requested.
    pub party_id: PartyId,
}

/// Request to sign the `nonce` with the rp's signing key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignNonceRequest {
    /// The rp that signs the nonce
    pub rp_id: RpId,
    /// The nonce to sign
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub nonce: ark_babyjubjub::Fq,
}

/// Response with the signed nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignNonceResponse {
    /// The signature
    pub signature: k256::ecdsa::Signature,
}

impl ChainEvent {
    /// Convenience constructor for a round-1 event.
    pub fn round1_event(rp_id: RpId, degree: u16) -> Self {
        Self::SecretGenRound1(SecretGenRound1Event { rp_id, degree })
    }

    /// Convenience constructor for a round-2 event.
    pub fn round2_event(rp_id: RpId, keys: PeerPublicKeyList) -> Self {
        Self::SecretGenRound2(SecretGenRound2Event { rp_id, keys })
    }

    /// Convenience constructor for a finalize event.
    pub fn finalize_event(
        rp_id: RpId,
        rp_public_key: k256::PublicKey,
        ciphers: Vec<RpSecretGenCiphertext>,
    ) -> Self {
        Self::SecretGenFinalize(SecretGenFinalizeEvent {
            rp_id,
            rp_public_key,
            ciphers,
        })
    }
}
