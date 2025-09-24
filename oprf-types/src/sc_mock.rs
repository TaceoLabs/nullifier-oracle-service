//! Types for communicating with the mock smart contract during staging tests.
//!
//! This module is only compiled when the `mock-chain-watcher` feature is enabled.  
//! It defines request/response types and event payloads exchanged with
//! the mock contract used in integration testing.

use serde::{Deserialize, Serialize};

use crate::{
    MerkleEpoch, MerkleRoot, RpId,
    chain::{ChainEvent, SecretGenFinalizeEvent, SecretGenRound1Event, SecretGenRound2Event},
    crypto::{PeerIdentifier, PeerPublicKeyList, RpSecretGenCiphertext},
};

/// Represents an update of the Merkle root for a specific epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleRootUpdate {
    /// The merkle root
    pub hash: MerkleRoot,
    /// The epoch of the new root
    pub epoch: MerkleEpoch,
}

/// Request for `fetchRoots`.
///
/// Defines the amount of roots the OPRF-Service wants to load
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRootsRequest {
    /// The amount of roots to fetch (max value).
    pub amount: u32,
}

/// Request for `is_valid_epoch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsValidEpochRequest {
    /// The epoch to check
    pub epoch: MerkleEpoch,
}

/// Request sent to read events for a given peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadEventsRequest {
    /// Identifier of the peer whose events are requested.
    pub key: PeerIdentifier,
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
    pub fn finalize_event(rp_id: RpId, ciphers: Vec<RpSecretGenCiphertext>) -> Self {
        Self::SecretGenFinalize(SecretGenFinalizeEvent { rp_id, ciphers })
    }
}
