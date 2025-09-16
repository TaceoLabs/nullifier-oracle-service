//! # Oprf-Types
//!
//! This crate defines the core value types used throughout the OPRF-Service/Client,
//! such as epochs, relying-party identifiers, and Merkle roots.
//! These types are thin, strongly-typed wrappers around primitive values
//! (like `u128` or `ark_babyjubjub::Fq`) and provide custom serialization
//! and display implementations for consistent formatting across the codebase.
//!
//! Use these types to pass and store identifiers and cryptographic values
//! in a type-safe way without worrying about manual (de)serialization.
use std::fmt;

use oprf_core::ark_serde_compat;
use serde::{Deserialize, Serialize};

pub mod api;

/// Represents an epoch of a merkle-root. Users will provide a `MrEpoch` and retrieve the associated [`MerkleRoot`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct MerkleEpoch(u128);

/// Represents an epoch for the key share.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct KeyEpoch(u128);

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

impl KeyEpoch {
    /// Converts the key epoch to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }
}

impl MerkleRoot {
    /// Converts the merkle-root hash to its inner value, which is an element in the base field of BabyJubJub (which is equivalent to BN254 scalar field)
    pub fn into_inner(self) -> ark_babyjubjub::Fq {
        self.0
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl fmt::Display for KeyEpoch {
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
