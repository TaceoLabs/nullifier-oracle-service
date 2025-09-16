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

use oprf_core::{
    ark_serde_compat::{self, groth16::Groth16Proof},
    ddlog_equality::{
        DLogEqualityChallenge, DLogEqualityProofShare, PartialDLogEqualityCommitments,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{KeyEpoch, MerkleEpoch, RpId};

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Deserialize)]
pub struct OprfRequest {
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Zero-knowledge proof provided by the user.
    pub user_proof: Groth16Proof,
    /// Input point `B` of the OPRF, serialized as a BabyJubJub affine point.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub point_b: ark_babyjubjub::EdwardsAffine,
    /// Identifies the relying party’s key for this request.
    pub rp_key_id: KeyIdentifier,
    /// The Merkle epoch associated with this request.
    pub merkle_epoch: MerkleEpoch,
}

/// Identifies a relying party’s key by party and epoch.
#[derive(Clone, Debug, Deserialize)]
pub struct KeyIdentifier {
    /// ID of the relying party.
    pub rp_id: RpId,
    /// Epoch of the key.
    pub key_epoch: KeyEpoch,
}

/// Server response to an [`OprfRequest`].
#[derive(Debug, Serialize)]
pub struct OprfResponse {
    /// ID of the request being answered.
    pub request_id: Uuid,
    /// Server’s partial commitments for the discrete log equality proof.
    pub commitments: PartialDLogEqualityCommitments,
}

/// A request from the client to complete the DLog equality challenge.
#[derive(Deserialize)]
pub struct ChallengeRequest {
    /// ID of the original OPRF request.
    pub request_id: Uuid,
    /// The challenge to respond to.
    pub challenge: DLogEqualityChallenge,
    /// Identifies the relying party’s key for this challenge.
    pub rp_key_id: KeyIdentifier,
}

/// Server response to a [`ChallengeRequest`].
#[derive(Debug, Serialize)]
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
