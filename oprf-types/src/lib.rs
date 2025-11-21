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

use alloy::primitives::{U160, U256};
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
pub struct OprfKeyId(U160);

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

impl OprfKeyId {
    /// Converts the RP id to an u128
    pub fn into_inner(self) -> U160 {
        self.0
    }

    /// Creates a new `OprfKeyId` by wrapping a `U160`
    pub fn new(value: U160) -> Self {
        Self(value)
    }
}

impl From<U160> for OprfKeyId {
    fn from(value: U160) -> Self {
        Self(value)
    }
}

impl fmt::Display for OprfKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", self.0))
    }
}

impl fmt::Display for ShareEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<OprfKeyId> for ark_babyjubjub::Fq {
    fn from(value: OprfKeyId) -> Self {
        let u256 = U256::from(value.0);
        // this works because we now that key-id has 160 bits
        ark_babyjubjub::Fq::new(ark_ff::BigInt(u256.into_limbs()))
    }
}
