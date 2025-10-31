use std::collections::HashMap;

use async_trait::async_trait;
use oprf_world_types::MerkleRoot;
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::merkle_watcher::{MerkleRootStore, MerkleWatcher, MerkleWatcherError};

pub(crate) struct TestMerkleWatcher {
    pub(crate) merkle_root_store: Mutex<MerkleRootStore>,
}

impl TestMerkleWatcher {
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
