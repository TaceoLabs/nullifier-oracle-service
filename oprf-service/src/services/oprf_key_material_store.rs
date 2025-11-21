//! This module provides [`OprfKeyMaterialStore`], which securely holds each RP's
//! DLog shares (per epoch) along with their ECDSA verifying key.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.  
//! Each RP's material is represented by [`OprfKeyMaterial`].

use oprf_core::{
    ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, DLogSessionShamir, DLogShareShamir,
        PartialDLogCommitmentsShamir,
    },
    shamir,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::v1::ShareIdentifier,
    crypto::{OprfPublicKey, PartyId},
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;

type OprfKeyMaterialStoreResult<T> = std::result::Result<T, OprfKeyMaterialStoreError>;

/// Errors returned by the [`OprfKeyMaterial`].
///
/// This error type is mostly used in API contexts, meaning it should be digested by the
/// [`crate::api::errors`] module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub enum OprfKeyMaterialStoreError {
    /// Cannot find the RP.
    #[error("Cannot find RP id: {0}")]
    UnknownRp(OprfKeyId),
    /// Cannot find a secret share for the epoch.
    #[error("Cannot find share with epoch: {0}")]
    UnknownShareEpoch(ShareEpoch),
}

/// Storage of the OPRF cryptographic material.
///
/// Includes the [`DLogShareShamir`] secret-share and the [`OprfPublicKey`].
#[derive(Default, Clone)]
pub struct OprfKeyMaterialStore(Arc<RwLock<HashMap<OprfKeyId, OprfKeyMaterial>>>);

/// The cryptographic material for one OPRF key.
///
/// Stores:
/// * A mapping of [`ShareEpoch`] → [`DLogShareShamir`]
/// * The [`OprfPublicKey`] associated with the share.
#[derive(Clone)]
pub struct OprfKeyMaterial {
    pub(crate) shares: HashMap<ShareEpoch, DLogShareShamir>,
    nullifier_key: OprfPublicKey,
}

impl OprfKeyMaterial {
    /// Creates a new [`OprfKeyMaterial`] from the provided shares and ECDSA public key.
    #[allow(dead_code)]
    pub(crate) fn new(
        shares: HashMap<ShareEpoch, DLogShareShamir>,
        nullifier_key: OprfPublicKey,
    ) -> Self {
        Self {
            shares,
            nullifier_key,
        }
    }

    /// Returns the [`DLogShareShamir`] for the given epoch, or `None` if not found.
    fn get_share(&self, epoch: ShareEpoch) -> Option<DLogShareShamir> {
        self.shares.get(&epoch).cloned()
    }

    /// Returns the [`OprfPublicKey`].
    fn get_oprf_public_key(&self) -> OprfPublicKey {
        self.nullifier_key
    }
}

impl OprfKeyMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub(crate) fn new(inner: HashMap<OprfKeyId, OprfKeyMaterial>) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the peer's partial contribution used in the DLogEqualityProof.
    /// The provided [`OprfShareIdentifier`] identifies the RP and the epoch of the share.
    ///
    /// Returns an error if the RP is unknown or the share for the epoch is not registered.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        share_identifier: &ShareIdentifier,
    ) -> OprfKeyMaterialStoreResult<(DLogSessionShamir, PartialDLogCommitmentsShamir)> {
        tracing::debug!("computing partial commitment");
        let share = self
            .get(share_identifier.oprf_key_id)
            .ok_or_else(|| OprfKeyMaterialStoreError::UnknownRp(share_identifier.oprf_key_id))?
            .get_share(share_identifier.share_epoch)
            .ok_or_else(|| {
                OprfKeyMaterialStoreError::UnknownShareEpoch(share_identifier.share_epoch)
            })?;
        Ok(DLogSessionShamir::partial_commitments(
            point_b,
            share,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness. The provided
    /// [`OprfShareIdentifier`] identifies the RP and the epoch of the key.
    ///
    /// Returns an error if the RP is unknown or the key epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session_id: Uuid,
        my_party_id: PartyId,
        session: DLogSessionShamir,
        challenge: DLogCommitmentsShamir,
        share_identifier: &ShareIdentifier,
    ) -> OprfKeyMaterialStoreResult<DLogProofShareShamir> {
        tracing::debug!("finalizing proof share");
        let rp_nullifier_key = self
            .get_oprf_public_key(share_identifier.oprf_key_id)
            .ok_or_else(|| OprfKeyMaterialStoreError::UnknownRp(share_identifier.oprf_key_id))?;
        let share = self
            .get(share_identifier.oprf_key_id)
            .ok_or_else(|| OprfKeyMaterialStoreError::UnknownRp(share_identifier.oprf_key_id))?
            .get_share(share_identifier.share_epoch)
            .ok_or_else(|| {
                OprfKeyMaterialStoreError::UnknownShareEpoch(share_identifier.share_epoch)
            })?;
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

    /// Retrieves the secret share for the given [`OprfShareIdentifier`].
    ///
    /// Returns `None` if the RP or share epoch is not found.
    fn get(&self, rp_id: OprfKeyId) -> Option<OprfKeyMaterial> {
        self.0.read().get(&rp_id).cloned()
    }

    /// Returns the [`OprfPublicKey`], if registered.
    pub(crate) fn get_oprf_public_key(&self, rp_id: OprfKeyId) -> Option<OprfPublicKey> {
        Some(self.0.read().get(&rp_id)?.get_oprf_public_key())
    }

    /// Adds OPRF key-material with epoch 0.
    ///
    /// Overwrites any existing entry.  
    /// Intended for creating new shares, not rotation.
    pub(super) fn add(
        &self,
        rp_id: OprfKeyId,
        oprf_public_key: OprfPublicKey,
        dlog_share: DLogShareShamir,
    ) {
        let mut shares = HashMap::new();
        shares.insert(ShareEpoch::default(), dlog_share);
        if self
            .0
            .write()
            .insert(
                rp_id,
                OprfKeyMaterial {
                    shares,
                    nullifier_key: oprf_public_key,
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
    pub(super) fn remove(&self, rp_id: OprfKeyId) {
        if self.0.write().remove(&rp_id).is_some() {
            tracing::debug!("removed {rp_id:?} material from OprfKeyMaterialStore");
        }
    }
}
