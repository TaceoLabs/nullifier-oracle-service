//! This module provides [`RpMaterialStore`], which securely holds each RP's
//! DLog shares (per epoch) along with their ECDSA verifying key.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.  
//! Each RP's material is represented by [`RpMaterial`].

use std::{collections::HashMap, sync::Arc};

use oprf_types::{RpId, ShareEpoch, api::v1::NullifierShareIdentifier};
use parking_lot::RwLock;

use crate::services::crypto_device::DLogShare;

/// Thread-safe storage of all cryptographic material for each relying party:
/// discrete-log shares **and** the ECDSA public key of the RP.
#[derive(Clone)]
pub(super) struct RpMaterialStore(Arc<RwLock<HashMap<RpId, RpMaterial>>>);

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
}

impl RpMaterial {
    /// Creates a new [`RpMaterial`] from the provided shares and ECDSA public key.
    #[allow(dead_code)]
    pub(crate) fn new(
        shares: HashMap<ShareEpoch, DLogShare>,
        public_key: k256::ecdsa::VerifyingKey,
    ) -> Self {
        Self { shares, public_key }
    }

    /// Returns the [`DLogShare`] for the given epoch, or `None` if not found.
    pub(super) fn get_share(&self, epoch: ShareEpoch) -> Option<DLogShare> {
        self.shares.get(&epoch).copied()
    }

    /// Returns the RP's ECDSA `VerifyingKey`.
    pub(super) fn get_public_key(&self) -> k256::ecdsa::VerifyingKey {
        self.public_key
    }
}

impl RpMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub(super) fn new(inner: HashMap<RpId, RpMaterial>) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Retrieves the secret share for the given [`NullifierShareIdentifier`].
    ///
    /// Returns `None` if the RP or share epoch is not found.
    pub(super) fn get(
        &self,
        key_identifier: &NullifierShareIdentifier,
    ) -> Option<ark_babyjubjub::Fr> {
        self.0
            .read()
            .get(&key_identifier.rp_id)?
            .get_share(key_identifier.share_epoch)
            .map(|share| share.0)
    }

    /// Returns the ECDSA `VerifyingKey` of the specified RP, if registered.
    pub(super) fn get_rp_public_key(&self, rp_id: RpId) -> Option<k256::ecdsa::VerifyingKey> {
        Some(self.0.read().get(&rp_id)?.get_public_key())
    }

    /// Adds a new RP entry with a secret share at epoch 0.
    ///
    /// Overwrites any existing entry.  
    /// Intended for creating new shares, not rotation.
    pub(super) fn add(
        &self,
        rp_id: RpId,
        public_key: k256::ecdsa::VerifyingKey,
        dlog_share: DLogShare,
    ) {
        let mut shares = HashMap::new();
        shares.insert(ShareEpoch::default(), dlog_share);
        if self
            .0
            .write()
            .insert(rp_id, RpMaterial { shares, public_key })
            .is_some()
        {
            tracing::warn!("overwriting share for {rp_id}");
        }
    }
}
