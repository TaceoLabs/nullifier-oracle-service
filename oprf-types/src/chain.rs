//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that peers send and receive on-chain.

use serde::{Deserialize, Serialize};

use crate::{
    RpId,
    crypto::{
        PartyId, PeerPublicKeyList, RpSecretGenCiphertext, RpSecretGenCiphertexts,
        RpSecretGenCommitment,
    },
};

/// Events emitted by the mock contract during key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainEvent {
    /// First-round key-generation event.
    SecretGenRound1(SecretGenRound1Event),
    /// Second-round key-generation event.
    SecretGenRound2(SecretGenRound2Event),
    /// Finalization event for key generation.
    SecretGenFinalize(SecretGenFinalizeEvent),
}

/// Represents the result of processing a chain event.
///
/// Each variant contains the processed data for a specific type of OPRF secret-generation contribution.
pub enum ChainEventResult {
    /// Output for handling key-generation round 1 event
    SecretGenRound1(SecretGenRound1Contribution),
    /// Output for handling key-generation round 2 event
    SecretGenRound2(SecretGenRound2Contribution),
    /// Output for handling key-generation finalize event
    SecretGenFinalize(SecretGenFinalizeContribution),
}

/// Payload of a first-round key-generation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Event {
    /// Identifier of the relying party this event belongs to.
    pub rp_id: RpId,
    /// The threshold for this shamir-sharing. Formally speaking, the degree of the polynomial the peer should create.
    pub degree: u16,
}

/// Payload of a second-round key-generation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Event {
    /// Identifier of the relying party this event belongs to.
    pub rp_id: RpId,
    /// List of the [`crate::crypto::PeerPublicKey`]s that participated in round 1.
    pub keys: PeerPublicKeyList,
}

/// Payload of a finalization event for key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenFinalizeEvent {
    /// Identifier of the relying party this event belongs to.
    pub rp_id: RpId,
    /// The public key of the RP to check the signature nonce.
    pub rp_public_key: k256::PublicKey,
    /// Commitments submitted in round 1.
    pub commitments: Vec<RpSecretGenCommitment>,
    /// Ciphertexts submitted in round 2.
    pub ciphers: Vec<RpSecretGenCiphertext>,
}

/// A first-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending peer’s identifier,
/// and its first-round [`RpSecretGenCommitment`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Contribution {
    /// Identifier of the relying party this contribution belongs to.
    pub rp_id: RpId,
    /// The peer that created this contribution.
    pub sender: PartyId,
    /// The peer’s first-round commitment.
    pub contribution: RpSecretGenCommitment,
}

/// A second-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending peer’s identifier,
/// and its second-round [`RpSecretGenCiphertexts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Contribution {
    /// Identifier of the relying party this contribution belongs to.
    pub rp_id: RpId,
    /// The peer that created this contribution.
    pub sender: PartyId,
    /// The peer’s second-round ciphertexts.
    pub contribution: RpSecretGenCiphertexts,
}

/// A finalization message for key generation submitted on-chain.
///
/// Contains only the relying-party identifier and the sending peer’s identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenFinalizeContribution {
    /// Identifier of the relying party this contribution belongs to.
    pub rp_id: RpId,
    /// The peer that created this contribution.
    pub sender: PartyId,
}
