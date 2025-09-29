//! Common cryptographic types used in the OPRF-nullifier service.
//!
//! This module defines the public keys, identifiers, commitments and
//! ciphertext structures exchanged between participants in the OPRF-
//! nullifier service.
//!
//! Main types:
//! * [`PartyId`]
//! * [`PeerPublicKey`]
//! * [`PeerPublicKeyList`]
//! * [`RpNullifierKey`]
//! * [`RpSecretGenCommitment`]
//! * [`RpSecretGenCiphertexts`] / [`RpSecretGenCiphertext`]

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

/// The party id of the OPRF-Peer.
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(u16);

/// The public key of an OPRF peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(transparent)]
pub struct PeerPublicKey(
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    ark_babyjubjub::EdwardsAffine,
);

/// A list of [`PeerPublicKey`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerPublicKeyList(Vec<PeerPublicKey>);

/// The public key of a relying party, used to verify computed nullifiers.
///
/// Constructed by multiplying the BabyJubJub generator with the secret shared among the OPRF peers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct RpNullifierKey(
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    ark_babyjubjub::EdwardsAffine,
);

/// A batch  of end-user public keys
///
/// Stored in the Merkle-Tree at the Smart Contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicKeyBatch {
    /// Values of the the public key (always len 7)
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_user_key_batch")]
    pub values: [ark_babyjubjub::EdwardsAffine; 7],
}

impl UserPublicKeyBatch {
    pub fn into_proof_input(self) -> [[ark_babyjubjub::Fq; 2]; 7] {
        self.values.map(|p| [p.x, p.y])
    }
}

/// The public contribution of one OPRF peer for the first round of the OPRF-nullifier generation protocol.
///
/// Contains the [`PeerPublicKey`] of the peer that created this contribution,
/// along with the public commitments to the random share and the polynomial.
///
/// See [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf)
/// for more information about the OPRF-nullifier generation protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCommitment {
    /// The OPRF peer that created this contribution.
    pub sender: PeerPublicKey,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The commitment to the random value sampled by the peer.
    pub comm_share: ark_babyjubjub::EdwardsAffine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    /// The commitment to the polynomial used to hide the sampled secret.
    pub comm_coeffs: ark_babyjubjub::Fq,
}

/// The public contribution of one OPRF peer for the second round of the OPRF-nullifier generation protocol.
///
/// Contains ciphertexts for all OPRF peers (including the peer itself) with the evaluations
/// of the polynomial generated in the first round.  
/// Wraps a `HashMap` mapping each [`PartyId`] to its [`RpSecretGenCiphertext`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpSecretGenCiphertexts(HashMap<PartyId, RpSecretGenCiphertext>);

/// A ciphertext for an OPRF peer used in round 2 of the OPRF-nullifier generation protocol.
///
/// Contains the [`PeerPublicKey`] of the sender, the ciphertext itself, and a nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCiphertext {
    /// The peer that created the ciphertext.
    pub sender: PeerPublicKey,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    /// The nonce used during encryption.
    pub nonce: ark_babyjubjub::Fq,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    /// The ciphertext.
    pub cipher: ark_babyjubjub::Fq,
}

impl PartyId {
    /// Converts to a `u16`.
    pub fn into_inner(self) -> u16 {
        self.0
    }
}

impl From<ark_babyjubjub::EdwardsAffine> for RpNullifierKey {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self(value)
    }
}

impl From<ark_babyjubjub::EdwardsAffine> for PeerPublicKey {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self(value)
    }
}

impl RpNullifierKey {
    /// Create a new `RpNullifierKey` by wrapping an BabyJubJub Point.
    pub fn new(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self::from(value)
    }

    /// Gets the inner value (a BabyJubJub point in Affine representation).
    pub fn inner(self) -> ark_babyjubjub::EdwardsAffine {
        self.0
    }
}

impl PeerPublicKey {
    /// Create a new `PeerPublicKey` by wrapping an BabyJubJub Point.
    pub fn new(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self::from(value)
    }

    /// Gets the inner value (a BabyJubJub point in Affine representation).
    pub fn inner(self) -> ark_babyjubjub::EdwardsAffine {
        self.0
    }
}

impl fmt::Display for RpNullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("NullifierPublicKey({})", self.0))
    }
}

impl fmt::Display for PeerPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("PeerPublicKey({})", self.0))
    }
}

impl From<Vec<PeerPublicKey>> for PeerPublicKeyList {
    fn from(value: Vec<PeerPublicKey>) -> Self {
        Self(value)
    }
}

impl IntoIterator for PeerPublicKeyList {
    type Item = PeerPublicKey;
    type IntoIter = std::vec::IntoIter<PeerPublicKey>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl PeerPublicKeyList {
    /// Creates a new public key list by wrapping a `Vec` of [`PeerPublicKeys`](PeerPublicKey).
    pub fn new(values: Vec<PeerPublicKey>) -> Self {
        Self::from(values)
    }

    /// Consumes this object and returns the inner value (`Vec<PeerPublicKey>`).
    pub fn into_inner(self) -> Vec<PeerPublicKey> {
        self.0
    }

    /// Returns the len of this list.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` iff the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl RpSecretGenCiphertexts {
    /// Returns the [`RpSecretGenCiphertext`] associated with the [`PartyId`]. Iff there is no ciphertext associated with this identifier, returns `None`.
    pub fn get_cipher_text(&self, filter: PartyId) -> Option<RpSecretGenCiphertext> {
        self.0.get(&filter).cloned()
    }
}

impl RpSecretGenCiphertexts {
    /// Creates a new instance by wrapping the provided value.
    pub fn new(value: HashMap<PartyId, RpSecretGenCiphertext>) -> Self {
        Self::from(value)
    }
}

impl From<HashMap<PartyId, RpSecretGenCiphertext>> for RpSecretGenCiphertexts {
    fn from(value: HashMap<PartyId, RpSecretGenCiphertext>) -> Self {
        Self(value)
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("PartyId({})", self.0))
    }
}

impl From<u16> for PartyId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<PartyId> for u16 {
    fn from(value: PartyId) -> Self {
        value.0
    }
}
