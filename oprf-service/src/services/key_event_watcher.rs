//! Defines the trait and types for key generation event listener services in the OPRF peer.
//!
//! A dynamic [`KeyGenEventListenerService`] type is provided for shared, Arc-based usage.

use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{
    chain::{ChainEvent, ChainEventResult},
    crypto::PartyId,
};
use tokio::sync::mpsc;

/// Type alias for a shared key generation event listener service.
pub(crate) type KeyGenEventListenerService = Arc<dyn KeyGenEventListener + Send + Sync>;

pub(crate) mod alloy_key_gen_watcher;

/// Service trait for subscribing to and reporting key generation events.
///
/// Implementations provide methods to:
/// - Subscribe to a stream of [`ChainEvent`]s.
/// - Report processed [`ChainEventResult`]s.
/// - Load the [`PartyId`] of this OPRF peer from chain.
///
/// The [`KeyGenEventListenerService`] type alias wraps the trait in an [`Arc`] for shared use.
///
/// # Errors
/// All methods return [`eyre::Result`] to propagate service or network errors.
#[async_trait]
pub(crate) trait KeyGenEventListener {
    /// Subscribes to a stream of chain events.
    async fn subscribe(&self) -> eyre::Result<mpsc::Receiver<ChainEvent>>;

    /// Reports the result of a processed chain event.
    async fn report_result(&self, result: ChainEventResult) -> eyre::Result<()>;

    /// Loads the party ID for this OPRF peer from chain.
    async fn load_party_id(&self) -> eyre::Result<PartyId>;
}
