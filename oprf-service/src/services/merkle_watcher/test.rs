use async_trait::async_trait;
use oprf_types::{MerkleEpoch, MerkleRoot, sc_mock::MerkleRootUpdate};
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::merkle_watcher::{MerkleRootStore, MerkleWatcher, MerkleWatcherError};

pub(crate) struct TestMerkleWatcher {
    pub(crate) merkle_root_store: Mutex<MerkleRootStore>,
}

impl TestMerkleWatcher {
    pub(crate) fn new(
        merkle_updates: Vec<MerkleRootUpdate>,
        max_merkle_store_size: usize,
        chain_epoch_max_difference: u128,
    ) -> eyre::Result<Self> {
        Ok(Self {
            merkle_root_store: Mutex::new(MerkleRootStore::new(
                merkle_updates,
                max_merkle_store_size,
                chain_epoch_max_difference,
            )?),
        })
    }
}

#[async_trait]
impl MerkleWatcher for TestMerkleWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn is_root_valid(
        &self,
        epoch: MerkleEpoch,
        root: MerkleRoot,
    ) -> Result<bool, MerkleWatcherError> {
        {
            let store = self.merkle_root_store.lock();
            // first check if the merkle root is already registered
            if let Some(known_root) = store.get_merkle_root(epoch) {
                tracing::trace!("cache hit");
                let valid = root == known_root;
                tracing::debug!("root valid: {valid}");
                return Ok(valid);
            } else {
                tracing::trace!("cache miss - check if too far in the future or past");
                store.is_sane_epoch(epoch)?;
                // is sane epoch - need to check on chain
                tracing::debug!("root valid: false");
                return Ok(false);
            }
        }
    }
}
