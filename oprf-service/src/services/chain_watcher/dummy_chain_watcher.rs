use async_trait::async_trait;
use oprf_types::{
    MerkleEpoch, MerkleRoot,
    chain::{ChainEvent, ChainEventResult},
    crypto::PartyId,
};

use crate::services::chain_watcher::{ChainWatcher, ChainWatcherError};

pub(crate) struct DummyWatcher;

#[async_trait]
impl ChainWatcher for DummyWatcher {
    async fn get_party_id(&self) -> Result<PartyId, ChainWatcherError> {
        todo!()
    }

    async fn get_merkle_root_by_epoch(
        &self,
        _epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError> {
        Err(ChainWatcherError::ChainCommunicationError(eyre::eyre!(
            "is a dummy"
        )))
    }

    async fn check_chain_events(&self) -> Result<Vec<ChainEvent>, ChainWatcherError> {
        Ok(Vec::new())
    }

    async fn report_chain_results(
        &self,
        _results: Vec<ChainEventResult>,
    ) -> Result<(), ChainWatcherError> {
        Ok(())
    }
}
