#![deny(missing_docs)]
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
//!
//! Use these types to pass, store, and (de)serialize identifiers and
//! cryptographic values in a type-safe way throughout your application.

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod api;
pub mod chain;
pub mod crypto;

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

impl ShareEpoch {
    /// Converts the key epoch to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new `ShareEpoch` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self(value)
    }
}

impl RpId {
    /// Converts the RP id to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self(value)
    }
}

impl From<u128> for RpId {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", self.0))
    }
}

impl fmt::Display for ShareEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<RpId> for ark_babyjubjub::Fq {
    fn from(value: RpId) -> Self {
        Self::from(value.0)
    }
}
