//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve [`crate::services::rp_material_store::RpMaterial`]s.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)

use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch, crypto::RpNullifierKey};

use crate::services::rp_material_store::{DLogShare, RpMaterialStore};

pub mod aws;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

pub(crate) struct StoreDLogShare {
    pub(crate) rp_id: RpId,
    pub(crate) public_key: k256::PublicKey,
    pub(crate) rp_nullifier_key: RpNullifierKey,
    pub(crate) share: DLogShare,
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of [`crate::services::rp_material_store::RpMaterial`]s.
#[async_trait]
pub(crate) trait SecretManager {
    /// Loads the DLog secrets and creates a [`RpMaterialStore`].
    async fn load_secrets(&self) -> eyre::Result<RpMaterialStore>;

    /// Stores the provided [`DLogShare`], the RP's ECDSA public key for the given [`RpId`] at epoch 0 and the computed [`RpNullifierKey`].
    ///
    /// This method is intended **only** for initializing a new RP. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()>;

    /// Removes all information stored associated with the specified [`RpId`].
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_dlog_share(&self, rp_id: RpId) -> eyre::Result<()>;

    /// Updates the [`DLogShare`] of an existing [`RpId`] to a new epoch.
    ///
    /// Use this method for updating existing shares. For creating a new share,
    /// use [`Self::store_dlog_share`].
    #[expect(dead_code)]
    async fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()>;
}
