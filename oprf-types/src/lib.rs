#![deny(missing_docs)]
//! # oprf-types
//!
//! Core type definitions for the OPRF service and client.
//!
//! This crate groups together the strongly-typed values and message
//! structures used across the OPRF system. It provides:
//!
//! * Thin wrappers around primitive values such as epochs, relying-party
//!   identifiers, and Merkle roots, with consistent serialization and
//!   display implementations.
//! * Cryptographic types used in the OPRF protocol (see [`crypto`] module).
//! * On-chain contribution types exchanged during key generation (see
//!   [`chain`] module).
//! * API versioned types for client/server communication (see [`api`] module).
//! * Optional types for communicating with the mock smart contract used in
//!   staging tests (see [`sc_mock`] module, enabled with the
//!   `mock-chain-watcher` feature).
//!
//! Use these types to pass, store, and (de)serialize identifiers and
//! cryptographic values in a type-safe way throughout your application.

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod api;
pub mod chain;
pub mod crypto;
#[cfg(feature = "mock-chain-watcher")]
pub mod sc_mock;

/// Represents an epoch of a merkle-root. Users will provide a `MerkleEpoch` and retrieve the associated [`MerkleRoot`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct MerkleEpoch(u128);

/// Represents an epoch for the DLog secret-share.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct ShareEpoch(u128);

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpId(u128);

/// Represents a merkle root hash. The inner type is a base field element from BabyJubJub for convenience instead of a scalar field element on BN254.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MerkleRoot(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_babyjubjub_base",
        deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base"
    )]
    ark_babyjubjub::Fq,
);

impl MerkleEpoch {
    /// Converts the merkle epoch to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }
}

impl ShareEpoch {
    /// Converts the key epoch to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new key epoch, starting at 0.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RpId {
    /// Converts the RP id to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self::from(value)
    }
}

impl MerkleRoot {
    /// Creates a new `MerkleRoot` by wrapping a base field element of BabyJubJub (which is equivalent to BN254 scalar field)
    pub fn new(f: ark_babyjubjub::Fq) -> Self {
        Self::from(f)
    }
    /// Converts the merkle-root hash to its inner value, which is an element in the base field of BabyJubJub (which is equivalent to BN254 scalar field)
    pub fn into_inner(self) -> ark_babyjubjub::Fq {
        self.0
    }
}

impl From<u128> for RpId {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<ark_babyjubjub::Fq> for MerkleRoot {
    fn from(value: ark_babyjubjub::Fq) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("RpId({})", self.0))
    }
}

impl fmt::Display for ShareEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl fmt::Display for MerkleEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<RpId> for ark_babyjubjub::Fq {
    fn from(value: RpId) -> Self {
        Self::from(value.0)
    }
}
