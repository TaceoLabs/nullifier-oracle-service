#[cfg(feature = "mock-chain-watcher")]
mod http_mock;

use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "mock-chain-watcher")]
pub(crate) use http_mock::spawn_mock_watcher;
use oprf_types::{MerkleEpoch, MerkleRoot};

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type ChainWatcherService = Arc<dyn ChainWatcher + Send + Sync>;

/// TODO
#[derive(Debug, thiserror::Error)]
pub(crate) enum ChainWatcherError {
    #[error("Cannot find epoch: {0:?}")]
    UnknownEpoch(MerkleEpoch),
    #[error("Could not check chain events: {0:?}")]
    #[expect(dead_code)]
    CouldNotCheckChainEvents(#[source] eyre::Report),
}

#[async_trait]
pub(crate) trait ChainWatcher {
    /// Retrieves a merkle root by epoch.
    ///
    /// If the epoch is in the cache immediately returns the merkle root.
    /// If the epoch is not in the cache potentially refreshes if epoch not too far in the future.
    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError>;

    /// TODO
    async fn check_chain_events(&self) -> Result<(), ChainWatcherError>;
}
