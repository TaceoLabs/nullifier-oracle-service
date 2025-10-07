//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve cryptographic material such as
//! [`PeerPrivateKey`]s and [`RpMaterial`]s.
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)
//! - test secret manager (contains initially provided secrets)

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch};

use crate::services::crypto_device::{DLogShare, PeerPrivateKey, dlog_storage::RpMaterial};

pub mod aws;
#[cfg(test)]
pub(crate) mod test;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of [`PeerPrivateKey`]s and [`RpMaterial`]s.
#[async_trait]
pub(crate) trait SecretManager {
    /// Loads the private key and the [`RpMaterial`] for the provided [`RpId`]s.
    ///
    /// The private key is used for Diffie-Hellman with the smart contract.
    /// Each RP has a dedicated share per epoch and an associated
    /// `ECDSA PublicKey`..
    async fn load_secrets(&self) -> eyre::Result<(PeerPrivateKey, HashMap<RpId, RpMaterial>)>;

    /// Stores the provided [`DLogShare`] and the RP's ECDSA public key for the given [`RpId`] at epoch 0.
    ///
    /// This method is intended **only** for initializing a new RP. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    async fn store_dlog_share(
        &self,
        rp_id: RpId,
        public_key: k256::PublicKey,
        share: DLogShare,
    ) -> eyre::Result<()>;

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
