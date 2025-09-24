//! # ChainWatcher module
//!
//! Defines the trait and types for services that watch blockchains in the OPRF peer.
//!
//! The [`ChainWatcher`] trait is used by the service to:
//! - Retrieve Merkle roots for given epochs.
//! - Poll or receive new chain events (e.g., secret generation contributions, finalization events).
//! - Report results of processed chain events back to the chain.
//!
//! Implementations may use the provided [`MerkleRootStore`] to track recent Merkle roots, which
//! automatically maintains a capped, ordered store and handles epoch sanity checks. Custom
//! stores can also be provided if needed.
//!
//! A dynamic [`ChainWatcherService`] type is provided for Arc-based usage with async runtimes
//! such as Axum.

#[cfg(feature = "mock-chain-watcher")]
mod http_mock;

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
#[cfg(feature = "mock-chain-watcher")]
pub(crate) use http_mock::init;
use oprf_types::{
    MerkleEpoch, MerkleRoot,
    chain::{ChainEvent, ChainEventResult},
    sc_mock::MerkleRootUpdate,
};
use tracing::instrument;

use crate::{config::OprfPeerConfig, metrics::METRICS_MERKLE_COUNT};

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type ChainWatcherService = Arc<dyn ChainWatcher + Send + Sync>;

/// Errors returned by the [`ChainWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ChainWatcherError {
    #[error("Cannot find epoch: {0:?}")]
    UnknownEpoch(MerkleEpoch),
    #[error("Refusing to check, too far in future: {0:?}")]
    TooFarInFuture(MerkleEpoch),
    #[error("Refusing to check, too far in past: {0:?}")]
    TooFarInPast(MerkleEpoch),
    #[error("Cannot talk to chain: {0:?}")]
    ChainCommunicationError(#[from] eyre::Report),
}

/// Trait for services that watch blockchains for OPRF-related events.
/// Handling of those events checkout [`crate::services::event_handler::ChainEventHandler`].
///
/// Implementations may poll the chain, subscribe to events, or
/// otherwise track keygen/finalization contributions.
#[async_trait]
pub(crate) trait ChainWatcher {
    /// Retrieves a merkle root by epoch.
    ///
    /// May return immediately if the epoch is cached.
    /// May refresh state if epoch is not too far in the future.
    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError>;

    /// Checks for new chain events, like keygen contributions or finalizations.
    ///
    /// This method should only return the events that it observes and not care about handling the events.
    async fn check_chain_events(&self) -> Result<Vec<ChainEvent>, ChainWatcherError>;

    /// Reports processed chain results back to the blockchain or monitoring system.
    async fn report_chain_results(
        &self,
        results: Vec<ChainEventResult>,
    ) -> Result<(), ChainWatcherError>;
}

/// Stores Merkle roots with associated epochs.
///
/// Maintains a BTreeMap of epoch → root, automatically keeping the most recent roots
/// up to a configured maximum. Old roots are dropped when the store exceeds capacity.
#[derive(Debug, Clone)]
pub(crate) struct MerkleRootStore {
    store: BTreeMap<MerkleEpoch, MerkleRoot>,
    current_epoch: MerkleEpoch,
    config: Arc<OprfPeerConfig>,
}

impl MerkleRootStore {
    /// Creates a new Merkle root store from an initial list of [`MerkleRootUpdate`]s.
    ///
    /// Sorts updates by epoch, sets the current epoch to the latest one,
    /// and clips the store if it exceeds `max_merkle_store_size` from
    /// the config.
    /// Fails if the store size is zero or no updates are provided.
    pub(crate) fn new(
        mut merkle_updates: Vec<MerkleRootUpdate>,
        config: Arc<OprfPeerConfig>,
    ) -> eyre::Result<Self> {
        if config.max_merkle_store_size == 0 {
            eyre::bail!("Max merkle store size must be > 0");
        }
        if merkle_updates.is_empty() {
            eyre::bail!("Need to init store with at least one value");
        }
        merkle_updates.sort_by_key(|m| m.epoch);
        let current_epoch = merkle_updates.last().expect("is there").epoch;

        if merkle_updates.len() > config.max_merkle_store_size {
            tracing::info!(
                "will clip merkle store to size: {}",
                config.max_merkle_store_size
            );
        }
        let store = merkle_updates
            .into_iter()
            .rev()
            .map(|mu| (mu.epoch, mu.hash))
            .collect::<BTreeMap<_, _>>();
        metrics::counter!(METRICS_MERKLE_COUNT).absolute(store.len() as u64);
        tracing::info!(
            "starting with current epoch: {current_epoch} and cache size: {}",
            store.len()
        );
        Ok(Self {
            store,
            current_epoch,
            config,
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
            if self.store.len() > self.config.max_merkle_store_size {
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
    pub(crate) fn is_sane_epoch(&self, epoch: MerkleEpoch) -> Result<(), ChainWatcherError> {
        let max_future_diff = self.config.chain_epoch_max_difference;
        let max_past_diff = self.store.len() as u128 + self.config.chain_epoch_max_difference;
        match self.current_epoch.cmp(&epoch) {
            std::cmp::Ordering::Less
                if MerkleEpoch::diff(epoch, self.current_epoch) > max_future_diff =>
            {
                Err(ChainWatcherError::TooFarInFuture(epoch))
            }
            std::cmp::Ordering::Greater
                if MerkleEpoch::diff(epoch, self.current_epoch) > max_past_diff =>
            {
                Err(ChainWatcherError::TooFarInPast(epoch))
            }
            _ => Ok(()),
        }
    }
}
