//! This module provides functionality for watching and validating Merkle roots associated with
//! blockchain epochs. It includes:
//!
//! - A `MerkleWatcher` trait for services that validate Merkle roots.
//! - A `MerkleRootStore` for storing and Merkle roots with associated epochs.
//!
//! Current `MerkleWatcher` implementations:
//! - alloy (uses the alloy crate to interact with smart contracts)
//! - test (contains initially provided merkle roots)

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{MerkleEpoch, MerkleRoot};
use tracing::instrument;

use crate::metrics::METRICS_MERKLE_COUNT;

pub(crate) mod alloy_merkle_watcher;
#[cfg(test)]
pub(crate) mod test;

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type MerkleWatcherService = Arc<dyn MerkleWatcher + Send + Sync>;

/// Errors returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleWatcherError {
    #[error("Refusing to check, too far in future: {0:?}")]
    TooFarInFuture(MerkleEpoch),
    #[error("Refusing to check, too far in past: {0:?}")]
    TooFarInPast(MerkleEpoch),
    #[error("Cannot talk to chain: {0:?}")]
    ChainCommunicationError(#[from] eyre::Report),
}

/// Trait for services that watch blockchains for merkle root updates
/// and provide functionality to check if a given root is valid,
#[async_trait]
pub(crate) trait MerkleWatcher {
    /// Check if a merkle root is valid.
    async fn is_root_valid(
        &self,
        epoch: MerkleEpoch,
        root: MerkleRoot,
    ) -> Result<bool, MerkleWatcherError>;
}

/// Stores Merkle roots with associated epochs.
///
/// Maintains a BTreeMap of epoch → root, automatically keeping the most recent roots
/// up to a configured maximum. Old roots are dropped when the store exceeds capacity.
#[derive(Debug, Clone)]
pub(crate) struct MerkleRootStore {
    store: BTreeMap<MerkleEpoch, MerkleRoot>,
    current_epoch: MerkleEpoch,
    max_merkle_store_size: usize,
    chain_epoch_max_difference: u128,
}

impl MerkleRootStore {
    /// Creates a new Merkle root store.
    ///
    /// Clips the store if it exceeds `max_merkle_store_size`.
    /// Fails if `max_merkle_store_size` is 0.
    pub(crate) fn new(
        init_store: BTreeMap<MerkleEpoch, MerkleRoot>,
        max_merkle_store_size: usize,
        chain_epoch_max_difference: u128,
    ) -> eyre::Result<Self> {
        if max_merkle_store_size == 0 {
            eyre::bail!("Max merkle store size must be > 0");
        }
        let current_epoch = init_store.keys().last().copied().unwrap_or_default();

        if init_store.len() > max_merkle_store_size {
            tracing::info!("will clip merkle store to size: {max_merkle_store_size}");
        }
        let store = init_store
            .into_iter()
            .rev()
            .take(max_merkle_store_size)
            .collect::<BTreeMap<_, _>>();
        metrics::counter!(METRICS_MERKLE_COUNT).absolute(store.len() as u64);
        tracing::info!(
            "starting with current epoch: {current_epoch} and cache size: {}",
            store.len()
        );
        Ok(Self {
            store,
            current_epoch,
            max_merkle_store_size,
            chain_epoch_max_difference,
        })
    }

    /// Inserts a new Merkle root for a given epoch.
    ///
    /// If the epoch already exists, it replaces the previous root.
    /// Automatically drops the oldest root if the store exceeds the configured maximum size.
    #[instrument(level = "trace", skip(self))]
    pub(crate) fn insert(&mut self, epoch: MerkleEpoch, root: MerkleRoot) {
        if self.store.insert(epoch, root).is_some() {
            tracing::debug!("epoch {epoch} already registered - replaced");
        } else {
            tracing::trace!("registered new epoch: {epoch}");
            if self.store.len() > self.max_merkle_store_size {
                // we need to drop one
                let (dropped, _) = self.store.pop_first().expect("is there for sure");
                tracing::trace!("dropped {dropped}");
            } else {
                metrics::counter!(METRICS_MERKLE_COUNT).increment(1);
            }
        }
    }

    /// Retrieves the Merkle root for a given epoch, if present.
    pub(crate) fn get_merkle_root(&self, epoch: MerkleEpoch) -> Option<MerkleRoot> {
        self.store.get(&epoch).copied()
    }

    /// Checks if an epoch is “sane” relative to the current store.
    ///
    /// Returns an error if the epoch is too far in the future or past
    /// based on configured maximum differences.
    pub(crate) fn is_sane_epoch(&self, epoch: MerkleEpoch) -> Result<(), MerkleWatcherError> {
        let max_future_diff = self.chain_epoch_max_difference;
        let max_past_diff = self.store.len() as u128 + self.chain_epoch_max_difference;
        match self.current_epoch.cmp(&epoch) {
            std::cmp::Ordering::Less
                if MerkleEpoch::diff(epoch, self.current_epoch) > max_future_diff =>
            {
                Err(MerkleWatcherError::TooFarInFuture(epoch))
            }
            std::cmp::Ordering::Greater
                if MerkleEpoch::diff(epoch, self.current_epoch) > max_past_diff =>
            {
                Err(MerkleWatcherError::TooFarInPast(epoch))
            }
            _ => Ok(()),
        }
    }
}
