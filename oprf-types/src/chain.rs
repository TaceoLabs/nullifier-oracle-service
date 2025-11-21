//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that peers send and receive on-chain.

use serde::{Deserialize, Serialize};

use crate::{
    OprfKeyId,
    crypto::{
        OprfPublicKey, PeerPublicKeyList, SecretGenCiphertext, SecretGenCiphertexts,
        SecretGenCommitment,
    },
};

/// Events emitted by the OprfKeyRegistry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainEvent {
    /// First-round key-generation event.
    SecretGenRound1(SecretGenRound1Event),
    /// Second-round key-generation event.
    SecretGenRound2(SecretGenRound2Event),
    /// Third-round key-generation event.
    SecretGenRound3(SecretGenRound3Event),
    /// Finalization event for key generation.
    SecretGenFinalize(SecretGenFinalizeEvent),
    /// Delete OPRF key material event.
    DeleteOprfKeyMaterial(OprfKeyId),
}

/// Represents the result of processing a chain event.
///
/// Each variant contains the processed data for a specific type of OPRF secret-generation contribution.
pub enum ChainEventResult {
    /// Output for handling key-generation round 1 event
    SecretGenRound1(SecretGenRound1Contribution),
    /// Output for handling key-generation round 2 event
    SecretGenRound2(SecretGenRound2Contribution),
    /// Output for handling key-generation round 3 event
    SecretGenRound3(SecretGenRound3Contribution),
}

/// Payload of a first-round key-generation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Event {
    /// Identifier this event belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The threshold for this shamir-sharing.
    pub threshold: u16,
}

/// Payload of a second-round key-generation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Event {
    /// Identifier this event belongs to.
    pub oprf_key_id: OprfKeyId,
    /// List of ephemeral public keys of the peers for this round (including own key).
    pub peers: PeerPublicKeyList,
}

/// Payload of a third-round event for key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound3Event {
    /// Identifier this event belongs to.
    pub oprf_key_id: OprfKeyId,
    /// Ciphertexts submitted in round 2.
    pub ciphers: Vec<SecretGenCiphertext>,
}

/// Payload of a finalization event for key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenFinalizeEvent {
    /// Identifier this event belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The computed OPRF public-key
    pub oprf_public_key: OprfPublicKey,
}

/// A first-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending peer’s identifier,
/// and its first-round [`SecretGenCommitment`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Contribution {
    /// Identifier of key this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The peer’s first-round commitment.
    pub contribution: SecretGenCommitment,
}

/// A second-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending peer’s identifier,
/// and its second-round [`SecretGenCiphertexts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The peer’s second-round ciphertexts.
    pub contribution: SecretGenCiphertexts,
}

/// A finalization message for key generation submitted on-chain.
///
/// Contains only the relying-party identifier. Finalize simply notifies
/// everyone that the sending peer successfully computed its share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound3Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
}
