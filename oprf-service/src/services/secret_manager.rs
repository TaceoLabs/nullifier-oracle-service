//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `OprfKeyMaterial`.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)

use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};

use crate::services::oprf_key_material_store::OprfKeyMaterialStore;

pub mod aws;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Data required to store a new DLog share.
pub struct StoreDLogShare {
    /// The OPRF public-key associated with this [`DLogShareShamir`].
    pub oprf_key_id: OprfKeyId,
    /// The created public part of the OPRF key
    pub oprf_public_key: OprfPublicKey,
    /// The actual secret-share from the created secret part of the nullifier key
    pub share: DLogShareShamir,
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `OprfKeyMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Loads the wallet private key from the secret-manager.
    ///
    /// If the secret-manager can't find a secret, it shall create a new one, store it and then return the new one.
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner>;

    /// Loads the DLog secrets and creates a [`OprfKeyMaterialStore`].
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore>;

    /// Stores the provided [`DLogShareShamir`] for the given [`OprfKeyId`] at epoch 0 and the computed [`OprfPublicKey`].
    ///
    /// This method is intended **only** for initializing a new RP. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()>;

    /// Removes all information stored associated with the specified [`OprfKeyId`].
    ///
    /// Certain secret-managers might not be able to immediately delete the secret. In that case it shall mark the secret for deletion.
    async fn remove_dlog_share(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()>;

    /// Updates the [`DLogShareShamir`] of an existing [`OprfKeyId`] to a new epoch.
    ///
    /// Use this method for updating existing shares. For creating a new share,
    /// use [`Self::store_dlog_share`].
    async fn update_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()>;
}
