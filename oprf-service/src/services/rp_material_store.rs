//! This module provides [`RpMaterialStore`], which securely holds each RP's
//! DLog shares (per epoch) along with their ECDSA verifying key.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.  
//! Each RP's material is represented by [`RpMaterial`].

use oprf_core::{
    ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, DLogSessionShamir, DLogShareShamir,
        PartialDLogCommitmentsShamir,
    },
    shamir,
};
use oprf_types::{
    RpId, ShareEpoch,
    api::v1::{NullifierShareIdentifier, PublicRpMaterial},
    crypto::{PartyId, RpNullifierKey},
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;

type RpMaterialStoreResult<T> = std::result::Result<T, RpMaterialStoreError>;

/// Errors returned by the [`RpMaterialStore`].
///
/// This error type is mostly used in API contexts, meaning it should be digested by the
/// [`crate::api::errors`] module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub enum RpMaterialStoreError {
    /// Cannot find the RP.
    #[error("Cannot find RP id: {0}")]
    UnknownRp(RpId),
    /// Cannot find a secret share for the epoch.
    #[error("Cannot find share with epoch: {0}")]
    UnknownShareEpoch(ShareEpoch),
    /// Cannot verify nonce signature.
    #[error(transparent)]
    NonceSignatureError(#[from] k256::ecdsa::Error),
}

/// Thread-safe storage of all cryptographic material for each relying party:
/// discrete-log shares **and** the ECDSA public key of the RP.
#[derive(Default, Clone)]
pub struct RpMaterialStore(Arc<RwLock<HashMap<RpId, RpMaterial>>>);

/// Holds all cryptographic material for a single relying party (RP).
///
/// Stores:
/// * A mapping of [`ShareEpoch`] → [`DLogShareShamir`]
/// * The RP's ECDSA `VerifyingKey` used for nonce-signature verification.
///
/// This struct is typically wrapped in a larger storage type (e.g. `RpMaterialStore`)
/// to manage multiple RPs.
#[derive(Clone)]
pub struct RpMaterial {
    pub(crate) shares: HashMap<ShareEpoch, DLogShareShamir>,
    public_key: k256::ecdsa::VerifyingKey,
    nullifier_key: RpNullifierKey,
}

impl RpMaterial {
    /// Creates a new [`RpMaterial`] from the provided shares and ECDSA public key.
    #[allow(dead_code)]
    pub(crate) fn new(
        shares: HashMap<ShareEpoch, DLogShareShamir>,
        public_key: k256::ecdsa::VerifyingKey,
        nullifier_key: RpNullifierKey,
    ) -> Self {
        Self {
            shares,
            public_key,
            nullifier_key,
        }
    }

    /// Returns the [`DLogShareShamir`] for the given epoch, or `None` if not found.
    fn get_share(&self, epoch: ShareEpoch) -> Option<DLogShareShamir> {
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
    ) -> RpMaterialStoreResult<(DLogSessionShamir, PartialDLogCommitmentsShamir)> {
        tracing::debug!("computing partial commitment");
        let share = self
            .get(share_identifier.rp_id)
            .ok_or_else(|| RpMaterialStoreError::UnknownRp(share_identifier.rp_id))?
            .get_share(share_identifier.share_epoch)
            .ok_or_else(|| RpMaterialStoreError::UnknownShareEpoch(share_identifier.share_epoch))?;
        Ok(DLogSessionShamir::partial_commitments(
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
        session: DLogSessionShamir,
        challenge: DLogCommitmentsShamir,
        share_identifier: &NullifierShareIdentifier,
    ) -> RpMaterialStoreResult<DLogProofShareShamir> {
        tracing::debug!("finalizing proof share");
        let rp_nullifier_key = self
            .get_rp_nullifier_key(share_identifier.rp_id)
            .ok_or_else(|| RpMaterialStoreError::UnknownRp(share_identifier.rp_id))?;
        let share = self
            .get(share_identifier.rp_id)
            .ok_or_else(|| RpMaterialStoreError::UnknownRp(share_identifier.rp_id))?
            .get_share(share_identifier.share_epoch)
            .ok_or_else(|| RpMaterialStoreError::UnknownShareEpoch(share_identifier.share_epoch))?;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        Ok(session.challenge(
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
    fn get(&self, rp_id: RpId) -> Option<RpMaterial> {
        self.0.read().get(&rp_id).cloned()
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
        dlog_share: DLogShareShamir,
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
