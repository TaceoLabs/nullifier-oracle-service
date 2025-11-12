//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve `RpMaterial`.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)

use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch, crypto::RpNullifierKey};
use secrecy::SecretString;

use crate::services::rp_material_store::{DLogShare, RpMaterialStore};

pub(crate) mod aws;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Data required to store a new RP's DLog share.
///
/// Contains all the information needed to initialize a new RP's
/// cryptographic material in the secret manager.
pub struct StoreDLogShare {
    /// The rp id associated with this [`DLogShare`].
    pub rp_id: RpId,
    /// The public key of the RP
    pub public_key: k256::PublicKey,
    /// The created public part of the nullifier key
    pub rp_nullifier_key: RpNullifierKey,
    /// The actual secret-share from the created secret part of the nullifier key
    pub share: DLogShare,
}

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of `RpMaterial`.
#[async_trait]
pub trait SecretManager {
    /// Loads the wallet private key from the secret-manager.
    ///
    /// If the secret-manager can't find a secret, it shall create a new one, store it and then return the new one.
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<SecretString>;
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
    async fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()>;
}
