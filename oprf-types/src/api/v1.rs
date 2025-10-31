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

use oprf_core::ddlog_equality::{
    DLogEqualityCommitments, DLogEqualityProofShare, PartialDLogEqualityCommitments,
};
use oprf_zk::groth16_serde::Groth16Proof;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::{RpId, ShareEpoch, crypto::PartyId};

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct OprfRequest<OprfRequestAuth>
where
    OprfRequestAuth: Clone + Serialize + DeserializeOwned,
{
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Zero-knowledge proof provided by the user.
    pub proof: Groth16Proof,
    /// Input point `B` of the OPRF, serialized as a BabyJubJub affine point.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub blinded_query: ark_babyjubjub::EdwardsAffine,
    /// Identifies the relying party’s and the epoch of the used share
    pub rp_identifier: NullifierShareIdentifier,
    /// The action
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq")]
    pub nonce: ark_babyjubjub::Fq,
    /// The additional authentication info for this request
    pub auth: OprfRequestAuth,
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
    pub challenge: DLogEqualityCommitments,
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

impl<OprfReqestAuth> fmt::Debug for OprfRequest<OprfReqestAuth>
where
    OprfReqestAuth: Clone + Serialize + DeserializeOwned,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("A", &self.blinded_query.to_string())
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
