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

use std::{fmt, ops::Sub, str::FromStr};

use alloy::primitives::U256;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod chain;
pub mod crypto;

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

    /// Creates a new `MerkleEpoch` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// Increases the epoch by one.
    pub fn inc(&mut self) -> Self {
        self.0 += 1;
        *self
    }

    /// Returns the absolute difference between two epochs.
    pub fn diff(self, other: Self) -> u128 {
        match self.cmp(&other) {
            std::cmp::Ordering::Less => (other - self).into_inner(),
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => (self - other).into_inner(),
        }
    }
}

impl Sub for MerkleEpoch {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

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

impl FromStr for MerkleRoot {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ark_babyjubjub::Fq::from_str(s)?))
    }
}

impl From<U256> for MerkleRoot {
    fn from(value: U256) -> Self {
        Self(ark_babyjubjub::Fq::new(ark_ff::BigInt(value.into_limbs())))
    }
}

impl From<MerkleRoot> for U256 {
    fn from(value: MerkleRoot) -> Self {
        U256::from_limbs(value.0.into_bigint().0)
    }
}

impl From<u128> for RpId {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<u128> for MerkleEpoch {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<U256> for MerkleEpoch {
    fn from(value: U256) -> Self {
        Self(u128::try_from(value).unwrap())
    }
}

impl From<u64> for MerkleEpoch {
    fn from(value: u64) -> Self {
        Self(u128::from(value))
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
