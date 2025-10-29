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

use std::{fmt, ops::Index};

use oprf_zk::groth16_serde::Groth16Proof;
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

/// A batch of end-user public keys
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
    /// Convert to inner `[ark_babyjubjub::EdwardsAffine; 7]`.
    pub fn into_inner(self) -> [ark_babyjubjub::EdwardsAffine; 7] {
        self.values
    }
}

/// The public contribution of one OPRF peer for the first round of the OPRF-nullifier generation protocol.
///
/// Contains the public commitments to the random share and the polynomial.
///
/// See [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf)
/// for more information about the OPRF-nullifier generation protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCommitment {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The commitment to the random value sampled by the peer.
    pub comm_share: ark_babyjubjub::EdwardsAffine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq")]
    /// The commitment to the polynomial used to hide the sampled secret.
    pub comm_coeffs: ark_babyjubjub::Fq,
}

/// The public contribution of one OPRF peer for the second round of the OPRF-nullifier generation protocol.
///
/// Contains ciphertexts for all OPRF peers (including the peer itself) with the evaluations
/// of the polynomial generated in the first round. The ciphertexts of the peers
/// is sorted according to their respective party ID.  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCiphertexts {
    /// The proof that the ciphertexts were computed correctly
    pub proof: Groth16Proof,
    /// All ciphers for peers (including peer itself).
    pub ciphers: Vec<RpSecretGenCiphertext>,
}

/// A ciphertext for an OPRF peer used in round 2 of the OPRF-nullifier generation protocol.
///
/// Contains the [`PeerPublicKey`] of the sender, the ciphertext itself, and a nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSecretGenCiphertext {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq")]
    /// The nonce used during encryption.
    pub nonce: ark_babyjubjub::Fq,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fq")]
    /// The ciphertext.
    pub cipher: ark_babyjubjub::Fq,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    /// The commitment to the encrypted value. Computed as xG, where x
    /// is the plaintext and G the generator of BabyJubJub.
    pub commitment: ark_babyjubjub::EdwardsAffine,
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
    /// Creates a new instance by wrapping the provided value.
    pub fn new(proof: Groth16Proof, ciphers: Vec<RpSecretGenCiphertext>) -> Self {
        Self { proof, ciphers }
    }
}

impl RpSecretGenCiphertext {
    /// Creates a new ciphertext contribution for an OPRF-Peer by wrapping a nonce, a ciphertext and a commitment to the plain text.
    pub fn new(
        cipher: ark_babyjubjub::Fq,
        commitment: ark_babyjubjub::EdwardsAffine,
        nonce: ark_babyjubjub::Fq,
    ) -> Self {
        Self {
            nonce,
            cipher,
            commitment,
        }
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

impl Index<usize> for PeerPublicKeyList {
    type Output = PeerPublicKey;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
