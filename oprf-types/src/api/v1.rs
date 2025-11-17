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

use oprf_core::ddlog_equality::shamir::{
    DLogCommitmentsShamir, DLogProofShareShamir, PartialDLogCommitmentsShamir,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::{
    RpId, ShareEpoch,
    crypto::{PartyId, RpNullifierKey},
};
use taceo_ark_serde_compat::babyjubjub;

/// The public components of the `RpMaterial`.
///
/// This contains
/// * ECDSA `VerifyingKey`
/// * [`RpNullifierKey`]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicRpMaterial {
    /// The public key used to verify the nonces of an Rp
    pub public_key: k256::ecdsa::VerifyingKey,
    /// The public part of the Nullifier Key.
    pub nullifier_key: RpNullifierKey,
}

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct OprfRequest<OprfRequestAuth>
where
    OprfRequestAuth: Clone + Serialize + DeserializeOwned,
{
    /// Unique ID of the request (used to correlate responses).
    pub request_id: Uuid,
    /// Input point `B` of the OPRF, serialized as a BabyJubJub affine point.
    #[serde(serialize_with = "babyjubjub::serialize_affine")]
    #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
    pub blinded_query: ark_babyjubjub::EdwardsAffine,
    /// Identifies the relying party’s and the epoch of the used share
    pub rp_identifier: NullifierShareIdentifier,
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
    pub commitments: PartialDLogCommitmentsShamir,
    /// The party ID of the peer
    pub party_id: PartyId,
}

/// A request from the client to complete the DLog equality challenge.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// ID of the original OPRF request.
    pub request_id: Uuid,
    /// The challenge to respond to.
    pub challenge: DLogCommitmentsShamir,
    /// Identifies the relying party’s and the epoch of the used share
    pub rp_identifier: NullifierShareIdentifier,
}

/// Server response to a [`ChallengeRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// ID of the request being answered.
    pub request_id: Uuid,
    /// Server’s proof share for the discrete log equality proof.
    pub proof_share: DLogProofShareShamir,
}

impl<OprfReqestAuth> fmt::Debug for OprfRequest<OprfReqestAuth>
where
    OprfReqestAuth: Clone + Serialize + DeserializeOwned,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("blinded_query", &self.blinded_query.to_string())
            .field("rp_identifier", &self.rp_identifier)
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
