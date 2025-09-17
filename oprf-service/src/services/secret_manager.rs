//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve cryptographic material such as
//! [`PeerPrivateKey`]s and [`DLogShare`]s.
//!
//! Current implementations:
//! - AWS (cloud storage)
//! - Local file storage (optional, behind `file-secret-manager` feature)
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch};

use crate::services::crypto_device::{DLogShare, PeerPrivateKey};

pub(crate) mod aws;
#[cfg(feature = "file-secret-manager")]
pub(crate) mod local;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Trait that implementations of secret managers must provide.
///
/// Handles persistence of [`PeerPrivateKey`]s and [`DLogShare`]s.
#[async_trait]
pub(crate) trait SecretManager {
    /// Loads the private key and all DLog shares for the provided [`RpId`]s.
    ///
    /// The private key is used for Diffie-Hellman with the smart contract.
    /// Each RP has a dedicated share per epoch. Implementations must return
    /// an error if any required share is missing.
    async fn load_secrets(
        &self,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<(
        PeerPrivateKey,
        HashMap<RpId, HashMap<ShareEpoch, DLogShare>>,
    )>;

    /// Stores the provided [`DLogShare`] for the given [`RpId`] at epoch 0.
    ///
    /// This method is intended **only** for initializing a new RP. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    ///
    /// This method is synchronous on purpose: [`crate::services::event_handler::handle_chain_events`]
    /// is CPU-bound, and we bridge into sync code for quick secret storage to
    /// avoid complicating the async CPU-intensive path.
    fn store_dlog_share(&self, rp_id: RpId, share: DLogShare) -> eyre::Result<()>;

    /// Updates the [`DLogShare`] of an existing [`RpId`] to a new epoch.
    ///
    /// Use this method for updating existing shares. For creating a new share,
    /// use [`Self::store_dlog_share`].
    ///
    /// This method is synchronous by design: [`crate::services::event_handler::handle_chain_events`]
    /// is CPU-bound, and we bridge into sync code to avoid blocking the async
    /// CPU-intensive path.
    #[expect(dead_code)]
    fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()>;
}
