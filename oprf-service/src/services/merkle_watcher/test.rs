//! Test Implementation of Merkle Watcher
//!
//! This module provides [`TestMerkleWatcher`], a simple in-memory implementation
//! of [`MerkleWatcher`] for testing purposes. It maintains a static store of
//! merkle roots without connecting to a blockchain.

use std::collections::HashMap;

use async_trait::async_trait;
use oprf_world_types::MerkleRoot;
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::merkle_watcher::{MerkleRootStore, MerkleWatcher, MerkleWatcherError};

/// In-memory merkle watcher for testing.
///
/// Maintains a static store of merkle roots without blockchain interaction.
pub(crate) struct TestMerkleWatcher {
    pub(crate) merkle_root_store: Mutex<MerkleRootStore>,
}

impl TestMerkleWatcher {
    /// Creates a new test merkle watcher with the given initial store.
    ///
    /// # Arguments
    /// * `init_store` - Initial merkle roots with their timestamps
    /// * `max_merkle_store_size` - Maximum number of merkle roots to store
    pub(crate) fn new(
        init_store: HashMap<MerkleRoot, u64>,
        max_merkle_store_size: usize,
    ) -> eyre::Result<Self> {
        Ok(Self {
            merkle_root_store: Mutex::new(MerkleRootStore::new(init_store, max_merkle_store_size)?),
        })
    }
}

#[async_trait]
impl MerkleWatcher for TestMerkleWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn is_root_valid(&self, root: MerkleRoot) -> Result<bool, MerkleWatcherError> {
        {
            let store = self.merkle_root_store.lock();
            Ok(store.contains_root(root))
        }
    }
}
