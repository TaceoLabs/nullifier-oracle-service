//! # ChainWatcher module
//!
//! Defines the trait and types for services that watch blockchains.
//!
//! The [`ChainWatcher`] trait is used by the service to:
//! - Retrieve Merkle roots for given epochs.
//! - Poll or receive new chain events (keygen contributions, finalization).
//! - Report results of processed chain events back to the chain.
//!
//! A dynamic [`ChainWatcherService`] type is provided for Arc-based usage
//! with async runtimes like Axum.
//!
#[cfg(feature = "mock-chain-watcher")]
mod http_mock;

use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "mock-chain-watcher")]
pub(crate) use http_mock::init;
use oprf_types::{
    MerkleEpoch, MerkleRoot,
    chain::{ChainEvent, ChainEventResult},
};

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type ChainWatcherService = Arc<dyn ChainWatcher + Send + Sync>;

/// Errors returned by the [`ChainWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ChainWatcherError {
    // #[error("Cannot find epoch: {0:?}")]
    // UnknownEpoch(MerkleEpoch),
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
