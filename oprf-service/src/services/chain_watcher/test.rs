use std::sync::Arc;

use async_trait::async_trait;
use oprf_types::{chain::ChainEvent, crypto::PartyId, sc_mock::MerkleRootUpdate};
use parking_lot::Mutex;

use crate::{
    config::OprfPeerConfig,
    services::chain_watcher::{
        ChainEventResult, ChainWatcher, ChainWatcherError, MerkleEpoch, MerkleRoot, MerkleRootStore,
    },
};

pub(crate) struct TestWatcher {
    pub(crate) merkle_root_store: Mutex<MerkleRootStore>,
}

impl TestWatcher {
    pub(crate) fn new(
        merkle_updates: Vec<MerkleRootUpdate>,
        config: Arc<OprfPeerConfig>,
    ) -> eyre::Result<Self> {
        Ok(Self {
            merkle_root_store: Mutex::new(MerkleRootStore::new(merkle_updates, config)?),
        })
    }
}

#[async_trait]
impl ChainWatcher for TestWatcher {
    async fn get_party_id(&self) -> Result<PartyId, ChainWatcherError> {
        Ok(PartyId::from(0))
    }

    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError> {
        self.merkle_root_store
            .lock()
            .get_merkle_root(epoch)
            .ok_or(ChainWatcherError::UnknownEpoch(epoch))
    }

    async fn check_chain_events(&self) -> Result<Vec<ChainEvent>, ChainWatcherError> {
        // Call to the mock smart contract
        Ok(Vec::new())
    }

    async fn report_chain_results(
        &self,
        _results: Vec<ChainEventResult>,
    ) -> Result<(), ChainWatcherError> {
        Ok(())
    }
}
