//! This module provides [`RpMaterialStore`], which securely holds each RP's
//! DLog shares (per epoch) along with their ECDSA verifying key.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.  
//! Each RP's material is represented by [`RpMaterial`].

use ark_ff::{BigInteger as _, PrimeField as _};
use k256::ecdsa::signature::Verifier;
use oprf_core::{
    ddlog_equality::{
        DLogEqualityCommitments, DLogEqualityProofShare, DLogEqualitySession,
        PartialDLogEqualityCommitments,
    },
    shamir,
};
use oprf_types::{
    RpId, ShareEpoch,
    api::v1::{NullifierShareIdentifier, PublicRpMaterial},
    crypto::{PartyId, RpNullifierKey},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

type RpMaterialStoreResult<T> = std::result::Result<T, RpMaterialStoreError>;

/// The errors the `RpMaterialStore
///
///` returns. This error types is mostly
/// used in API contexts, meaning it should be digested by the
/// [`crate::api::errors`] module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RpMaterialStoreError {
    /// Cannot find the RP.
    #[error("Cannot find RP id: {0}")]
    NoSuchRp(RpId),
    /// Cannot find a secret share for the given RP at the requested epoch.
    #[error("Cannot find share for Rp with epoch: {0:?}")]
    UnknownRpShareEpoch(NullifierShareIdentifier),
    /// Cannot verify nonce signature.
    #[error(transparent)]
    NonceSignatureError(#[from] k256::ecdsa::Error),
}

/// Thread-safe storage of all cryptographic material for each relying party:
/// discrete-log shares **and** the ECDSA public key of the RP.
#[derive(Clone)]
pub(crate) struct RpMaterialStore(Arc<RwLock<HashMap<RpId, RpMaterial>>>);

/// Holds all cryptographic material for a single relying party (RP).
///
/// Stores:
/// * A mapping of [`ShareEpoch`] → [`DLogShare`]
/// * The RP's ECDSA `VerifyingKey` used for nonce-signature verification.
///
/// This struct is typically wrapped in a larger storage type (e.g. `RpMaterialStore`)
/// to manage multiple RPs.
#[derive(Clone)]
pub(crate) struct RpMaterial {
    pub(crate) shares: HashMap<ShareEpoch, DLogShare>,
    public_key: k256::ecdsa::VerifyingKey,
    nullifier_key: RpNullifierKey,
}

/// Secret-share of an OPRF nullifier secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(crate) struct DLogShare(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_babyjubjub_fr",
        deserialize_with = "ark_serde_compat::deserialize_babyjubjub_fr"
    )]
    ark_babyjubjub::Fr,
);

impl From<ark_babyjubjub::Fr> for DLogShare {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShare> for ark_babyjubjub::Fr {
    fn from(value: DLogShare) -> Self {
        value.0
    }
}

impl RpMaterial {
    /// Creates a new [`RpMaterial`] from the provided shares and ECDSA public key.
    #[allow(dead_code)]
    pub(crate) fn new(
        shares: HashMap<ShareEpoch, DLogShare>,
        public_key: k256::ecdsa::VerifyingKey,
        nullifier_key: RpNullifierKey,
    ) -> Self {
        Self {
            shares,
            public_key,
            nullifier_key,
        }
    }

    /// Returns the [`DLogShare`] for the given epoch, or `None` if not found.
    fn get_share(&self, epoch: ShareEpoch) -> Option<DLogShare> {
        self.shares.get(&epoch).cloned()
    }

    /// Returns the RP's ECDSA `VerifyingKey`.
    fn get_public_key(&self) -> k256::ecdsa::VerifyingKey {
        self.public_key
    }

    /// Returns the RP's `RpNullifierKey`.
    fn get_nullifier_key(&self) -> RpNullifierKey {
        self.nullifier_key
    }
}

impl RpMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub(crate) fn new(inner: HashMap<RpId, RpMaterial>) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Verifies an ECDSA signature over a nonce and current_time_stamp for the given relying party.
    ///
    /// The BabyJubJub `nonce` is converted into `ark_ff::BigInt` and then into **little-endian bytes**.
    /// The `current_time_stamp` (given as u64 seconds since `UNIX_EPOCH`) is converted into **little-endian bytes**.
    /// The msg `nonce || current_time_stamp` is then verified against the stored ECDSA public key for `rp_id`
    /// using the provided `signature`.
    ///
    /// Returns `Ok(())` on success or an error if the relying party is unknown
    /// or the signature check fails.
    #[instrument(level = "debug", skip(self, nonce, signature))]
    pub(crate) fn verify_nonce_signature(
        &self,
        rp_id: RpId,
        nonce: ark_babyjubjub::Fq,
        current_time_stamp: u64,
        signature: &k256::ecdsa::Signature,
    ) -> RpMaterialStoreResult<()> {
        tracing::debug!("verifying nonce: {nonce}");
        let vk = self
            .get_rp_public_key(rp_id)
            .ok_or_else(|| RpMaterialStoreError::NoSuchRp(rp_id))?;
        let mut msg = Vec::new();
        msg.extend(nonce.into_bigint().to_bytes_le());
        msg.extend(current_time_stamp.to_le_bytes());
        vk.verify(&msg, signature)?;
        tracing::debug!("success");
        Ok(())
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the peer's partial contribution used in the DLogEqualityProof.
    /// The provided [`NullifierShareIdentifier`] identifies the RP and the epoch of the share.
    ///
    /// Returns an error if the RP is unknown or the share for the epoch is not registered.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        share_identifier: &NullifierShareIdentifier,
    ) -> RpMaterialStoreResult<(DLogEqualitySession, PartialDLogEqualityCommitments)> {
        tracing::debug!("computing partial commitment");
        let share = self.get(share_identifier).ok_or_else(|| {
            RpMaterialStoreError::UnknownRpShareEpoch(share_identifier.to_owned())
        })?;
        Ok(DLogEqualitySession::partial_commitments(
            point_b,
            share,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness. The provided
    /// [`NullifierShareIdentifier`] identifies the RP and the epoch of the key.
    ///
    /// Returns an error if the RP is unknown or the key epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session_id: Uuid,
        my_party_id: PartyId,
        session: DLogEqualitySession,
        challenge: DLogEqualityCommitments,
        share_identifier: &NullifierShareIdentifier,
    ) -> RpMaterialStoreResult<DLogEqualityProofShare> {
        tracing::debug!("finalizing proof share");
        let rp_nullifier_key = self
            .get_rp_nullifier_key(share_identifier.rp_id)
            .ok_or_else(|| RpMaterialStoreError::NoSuchRp(share_identifier.rp_id))?;
        let share = self.get(share_identifier).ok_or_else(|| {
            RpMaterialStoreError::UnknownRpShareEpoch(share_identifier.to_owned())
        })?;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        Ok(session.challenge_shamir(
            session_id,
            share,
            rp_nullifier_key.inner(),
            challenge,
            lagrange_coefficient,
        ))
    }
    /// Retrieves the secret share for the given [`NullifierShareIdentifier`].
    ///
    /// Returns `None` if the RP or share epoch is not found.
    fn get(&self, key_identifier: &NullifierShareIdentifier) -> Option<ark_babyjubjub::Fr> {
        self.0
            .read()
            .get(&key_identifier.rp_id)?
            .get_share(key_identifier.share_epoch)
            .map(|share| share.0)
    }

    /// Returns the ECDSA `VerifyingKey` of the specified RP, if registered.
    fn get_rp_public_key(&self, rp_id: RpId) -> Option<k256::ecdsa::VerifyingKey> {
        Some(self.0.read().get(&rp_id)?.get_public_key())
    }

    /// Returns the `RpNullifierKey` of the specified RP, if registered.
    fn get_rp_nullifier_key(&self, rp_id: RpId) -> Option<RpNullifierKey> {
        Some(self.0.read().get(&rp_id)?.get_nullifier_key())
    }

    /// Adds a new RP entry with a secret share at epoch 0.
    ///
    /// Overwrites any existing entry.  
    /// Intended for creating new shares, not rotation.
    pub(super) fn add(
        &self,
        rp_id: RpId,
        public_key: k256::ecdsa::VerifyingKey,
        nullifier_key: RpNullifierKey,
        dlog_share: DLogShare,
    ) {
        let mut shares = HashMap::new();
        shares.insert(ShareEpoch::default(), dlog_share);
        if self
            .0
            .write()
            .insert(
                rp_id,
                RpMaterial {
                    shares,
                    public_key,
                    nullifier_key,
                },
            )
            .is_some()
        {
            tracing::warn!("overwriting share for {rp_id}");
        }
    }

    /// Removes the RP entry associated with the provided [`RpId`].
    ///
    /// If the id is not registered, doesn't do anything.
    pub(super) fn remove(&self, rp_id: RpId) {
        if self.0.write().remove(&rp_id).is_some() {
            tracing::debug!("removed {rp_id:?} material from RpMaterialStore");
        }
    }

    /// Returns the [`PublicRpMaterial`] of the specified RP, if registered.
    /// This contains
    /// * ECDSA `VerifyingKey`
    /// * [`RpNullifierKey`]
    pub(crate) fn get_rp_public_material(&self, rp_id: RpId) -> Option<PublicRpMaterial> {
        let rp_material = self.0.read().get(&rp_id)?.to_owned();
        Some(PublicRpMaterial {
            public_key: rp_material.public_key,
            nullifier_key: rp_material.nullifier_key,
        })
    }
}
