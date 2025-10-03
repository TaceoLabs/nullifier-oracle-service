use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{
    chain::{ChainEvent, ChainEventResult},
    crypto::PartyId,
};
use tokio::sync::mpsc;

pub(crate) type KeyGenEventListenerService = Arc<dyn KeyGenEventListener + Send + Sync>;

pub(crate) mod alloy_key_gen_watcher;

#[async_trait]
pub(crate) trait KeyGenEventListener {
    async fn fetch_party_id(&self) -> eyre::Result<PartyId>;
    async fn subscribe(&self) -> eyre::Result<mpsc::Receiver<ChainEvent>>;
    async fn report_result(&self, result: ChainEventResult) -> eyre::Result<()>;
}
