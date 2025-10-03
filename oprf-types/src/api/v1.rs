//! # v1 API types
//!
//! Data transfer objects for the version 1 OPRF API.
//!
//! This module defines the request and response payloads exchanged
//! between clients and the server for the OPRF protocol, along with
//! identifiers used to reference keys and epochs. Types here wrap
//! cryptographic proofs and points with Serde (de)serialization so
//! they can be sent over the wire.
use std::fmt;

use ark_serde_compat::groth16::Groth16Proof;
use eddsa_babyjubjub::EdDSAPublicKey;
use oprf_core::ddlog_equality::{
    DLogEqualityChallenge, DLogEqualityProofShare, PartialDLogEqualityCommitments,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch, crypto::PartyId};

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequest {
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Zero-knowledge proof provided by the user.
    pub proof: Groth16Proof,
    /// Input point `B` of the OPRF, serialized as a BabyJubJub affine point.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub point_b: ark_babyjubjub::EdwardsAffine,
    /// Identifies the relying party’s and the epoch of the used share
    pub rp_identifier: NullifierShareIdentifier,
    /// The Merkle epoch associated with this request.
    pub merkle_epoch: MerkleEpoch,
    /// The Merkle root associated with this request.
    pub merkle_root: MerkleRoot,
    /// The action
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub nonce: ark_babyjubjub::Fq,
    /// The signature of the nonce
    pub signature: k256::ecdsa::Signature,
    /// The credential public key
    pub cred_pk: EdDSAPublicKey, // TODO maybe remove and get from chain
    /// The current time stamp (unix ms)
    pub current_time_stamp: u64,
    /// The depth of the credential in the merkle tree
    pub merkle_depth: u64,
}

/// Identifies the nullifier share to use for the OPRF computation by relying party ([`RpId`]) and [`ShareEpoch`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierShareIdentifier {
    /// ID of the relying party.
    pub rp_id: RpId,
    /// Epoch of the key.
    pub share_epoch: ShareEpoch,
}

/// Server response to an [`OprfRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct OprfResponse {
    /// ID of the request being answered.
    pub request_id: Uuid,
    /// Server’s partial commitments for the discrete log equality proof.
    pub commitments: PartialDLogEqualityCommitments,
    /// The party ID of the peer
    pub party_id: PartyId,
}

/// A request from the client to complete the DLog equality challenge.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// ID of the original OPRF request.
    pub request_id: Uuid,
    /// The challenge to respond to.
    pub challenge: DLogEqualityChallenge,
    /// Identifies the relying party’s and the epoch of the used share
    pub rp_identifier: NullifierShareIdentifier,
}

/// Server response to a [`ChallengeRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// ID of the request being answered.
    pub request_id: Uuid,
    /// Server’s proof share for the discrete log equality proof.
    pub proof_share: DLogEqualityProofShare,
}

impl fmt::Debug for OprfRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("A", &self.point_b.to_string())
            .field("proof", &"omitted")
            .finish()
    }
}

impl fmt::Debug for ChallengeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeRequest")
            .field("req_id", &self.request_id)
            .field("challenge", &"omitted")
            .finish()
    }
}
