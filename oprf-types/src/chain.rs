//! Types for on-chain messages.
//!
//! This module defines the events emitted by the blockchain
//! and the contributions submitted in response to these events.
//!
//! Use these types to encode the payloads that nodes send and receive on-chain.

use serde::{Deserialize, Serialize};

use crate::{
    OprfKeyId,
    crypto::{SecretGenCiphertexts, SecretGenCommitment},
};

/// A first-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending node’s identifier,
/// and its first-round [`SecretGenCommitment`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound1Contribution {
    /// Identifier of key this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The node’s first-round commitment.
    pub contribution: SecretGenCommitment,
}

/// A second-round key-generation contribution submitted on-chain.
///
/// Contains the relying-party identifier, the sending node’s identifier,
/// and its second-round [`SecretGenCiphertexts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound2Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
    /// The node’s second-round ciphertexts.
    pub contribution: SecretGenCiphertexts,
}

/// A finalization message for key generation submitted on-chain.
///
/// Contains only the relying-party identifier. Finalize simply notifies
/// everyone that the sending node successfully computed its share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGenRound3Contribution {
    /// Identifier this contribution belongs to.
    pub oprf_key_id: OprfKeyId,
}
