//! This module provides functionality for watching and validating Merkle roots. It includes:
//!
//! - A `MerkleWatcher` trait for services that validate Merkle roots.
//! - A `MerkleRootStore` for storing and Merkle roots with timestamps.
//!
//! Current `MerkleWatcher` implementations:
//! - alloy (uses the alloy crate to interact with smart contracts)
//! - test (contains initially provided merkle roots)

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::MerkleRoot;
use tracing::instrument;

use crate::metrics::METRICS_MERKLE_COUNT;

pub(crate) mod alloy_merkle_watcher;
#[cfg(test)]
pub(crate) mod test;

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type MerkleWatcherService = Arc<dyn MerkleWatcher + Send + Sync>;

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
#[error("chain communication error: {0}")]
pub(crate) struct MerkleWatcherError(pub String);

/// Trait for services that watch blockchains for merkle root updates
/// and provide functionality to check if a given root is valid,
#[async_trait]
pub(crate) trait MerkleWatcher {
    /// Check if a merkle root is valid.
    async fn is_root_valid(&self, root: MerkleRoot) -> Result<bool, MerkleWatcherError>;
}

/// Stores Merkle roots with associated timestamps.
///
/// Maintains a HashMap of root -> timestamp, automatically keeping the most recent roots
/// up to a configured maximum. Old roots are dropped when the store exceeds capacity.
#[derive(Debug, Clone)]
pub(crate) struct MerkleRootStore {
    store: HashMap<MerkleRoot, u64>,
    max_merkle_store_size: usize,
}

impl MerkleRootStore {
    /// Creates a new Merkle root store.
    ///
    /// Clips the store if it exceeds `max_merkle_store_size`.
    /// Fails if `max_merkle_store_size` is 0.
    pub(crate) fn new(
        store: HashMap<MerkleRoot, u64>,
        max_merkle_store_size: usize,
    ) -> eyre::Result<Self> {
        if max_merkle_store_size == 0 {
            eyre::bail!("Max merkle store size must be > 0");
        }
        if store.len() > max_merkle_store_size {
            eyre::bail!("initial store must be smaller than max");
        }
        metrics::counter!(METRICS_MERKLE_COUNT).absolute(store.len() as u64);
        tracing::info!("starting with store size: {}", store.len());
        Ok(Self {
            store,
            max_merkle_store_size,
        })
    }

    /// Inserts a new Merkle root.
    ///
    /// If the root already exists, it replaces the previous timestamp.
    /// Automatically drops the oldest root if the store exceeds the configured maximum size.
    #[instrument(level = "trace", skip(self))]
    pub(crate) fn insert(&mut self, root: MerkleRoot, timestamp: u64) {
        if self.store.insert(root, timestamp).is_some() {
            tracing::debug!("root {root} already registered - replaced");
        } else {
            tracing::trace!("registered new root: {root}");
            if self.store.len() > self.max_merkle_store_size {
                // find root with oldest timestamp
                let oldest_root = self
                    .store
                    .iter()
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(root, _)| *root)
                    .expect("store is not empty");
                tracing::debug!("store size exceeded, dropping oldest root: {oldest_root}");
                // drop the oldest root
                let dropped = self.store.remove(&oldest_root).expect("store not empty");
                tracing::trace!("dropped {dropped}");
            } else {
                metrics::counter!(METRICS_MERKLE_COUNT).increment(1);
            }
        }
    }

    /// Checks if the store contains a Merkle root
    ///
    /// Returns `true` if the root exists, `false` otherwise.
    pub(crate) fn contains_root(&self, root: MerkleRoot) -> bool {
        self.store.contains_key(&root)
    }
}
