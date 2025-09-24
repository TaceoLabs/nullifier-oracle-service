//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! persist and retrieve cryptographic material such as
//! [`PeerPrivateKey`]s and [`RpMaterial`]s.
//!
//! Current implementations:
//! - AWS (cloud storage)
//! - Local file storage (optional, behind `file-secret-manager` feature)
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch};

use crate::services::crypto_device::{DLogShare, PeerPrivateKey, dlog_storage::RpMaterial};

pub(crate) mod aws;
#[cfg(feature = "file-secret-manager")]
pub(crate) mod local;

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
    /// `ECDSA PublicKey`. Implementations must return
    /// an error if any required `RpMaterial` is missing.
    async fn load_secrets(
        &self,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<(PeerPrivateKey, HashMap<RpId, RpMaterial>)>;

    /// Stores the provided [`DLogShare`] and the RP's ECDSA public key for the given [`RpId`] at epoch 0.
    ///
    /// This method is intended **only** for initializing a new RP. For updating
    /// existing shares, use [`Self::update_dlog_share`].
    ///
    /// This method is synchronous by design: [`crate::services::event_handler::handle_chain_events`]
    /// runs CPU-bound work, but needs to call this method during
    /// the finalize event of nullifier secret-gen. Internally, can
    /// bridge into `async` land again but for simplicity at callsite,
    /// we provide this `sync` interface.
    fn store_dlog_share(
        &self,
        rp_id: RpId,
        public_key: k256::PublicKey,
        share: DLogShare,
    ) -> eyre::Result<()>;

    /// Updates the [`DLogShare`] of an existing [`RpId`] to a new epoch.
    ///
    /// Use this method for updating existing shares. For creating a new share,
    /// use [`Self::store_dlog_share`].
    ///
    /// This method is synchronous by design: [`crate::services::event_handler::handle_chain_events`]
    /// runs CPU-bound work, but needs to call this method during
    /// the finalize event of share refresh.
    /// Internally, can bridge into `async` land again but for
    /// simplicity at callsite, we provide this `sync` interface.
    #[expect(dead_code)]
    fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()>;
}
