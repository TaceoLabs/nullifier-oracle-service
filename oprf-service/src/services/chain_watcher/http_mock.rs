use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use eyre::Context;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    config::OprfConfig,
    services::chain_watcher::{
        ChainWatcher, ChainWatcherError, ChainWatcherService, MerkleEpoch, MerkleRoot,
    },
};

type MerkleRootStore = HashMap<MerkleEpoch, MerkleRoot>;

struct HttpMockWatcher {
    _config: Arc<OprfConfig>,
    _chain_url: String,
    _latest_epoch: MerkleEpoch,
    cancellation_token: CancellationToken,
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
}

#[instrument(level = "info", skip_all)]
pub(crate) async fn spawn_mock_watcher(
    config: Arc<OprfConfig>,
    cancellation_token: CancellationToken,
) -> eyre::Result<ChainWatcherService> {
    tracing::info!("spawning MOCK watcher - THIS WILL NOT TALK TO A REAL CHAIN");
    // assert that we are really in the dev environment
    config.environment.assert_is_dev();
    let mut interval = tokio::time::interval(config.chain_check_interval);
    let merkle_root_store = Arc::new(Mutex::new(MerkleRootStore::new()));
    let service = Arc::new(HttpMockWatcher {
        _config: Arc::clone(&config),
        _chain_url: config.chain_url.clone(),
        cancellation_token: cancellation_token.clone(),
        _latest_epoch: MerkleEpoch::default(),
        merkle_root_store,
    });
    tracing::info!("initial chain even check...");
    service
        .check_chain_events()
        .await
        .context("while initial chain events check")?;

    let service_clone = Arc::clone(&service);
    tracing::info!("starting periodic update task..");
    // spawn the periodic update task
    tokio::task::spawn(async move {
        // ignore the first tick as we load it anyways during startup
        interval.tick().await;
        loop {
            interval.tick().await;
            tracing::trace!("check chain event fired..");
            match service_clone.check_chain_events().await {
                Ok(_) => tracing::trace!("checked chain events.."),
                Err(err) => {
                    tracing::error!("could not check chain events: {err:?}");
                    cancellation_token.cancel();
                    break;
                }
            }
        }
    });
    Ok(service)
}

#[async_trait]
impl ChainWatcher for HttpMockWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError> {
        tracing::debug!("checking merkle root for epoch: {epoch:?}");
        let merkle_root = self.get_merkle_root_by_epoch_inner(epoch);

        if let Some(merkle_root) = merkle_root {
            tracing::debug!("returning root: {merkle_root:?}");
            Ok(merkle_root)
        } else {
            tracing::debug!("could not find merkle root");
            tracing::debug!("checking if we want to manually refresh..");

            // TODO this doesn't really work because latest epoch must be locked
            // self.latest_epoch
            //     .should_refresh(epoch, self.config.chain_epoch_max_difference)?;

            // epoch miss - maybe need to refresh
            match self.check_chain_events().await {
                Ok(_) => {
                    // checking one more time
                    self.get_merkle_root_by_epoch_inner(epoch)
                        .ok_or_else(|| ChainWatcherError::UnknownEpoch(epoch))
                }
                Err(err) => {
                    tracing::error!("could not check chain event: {err:?}");
                    self.cancellation_token.cancel();
                    Err(err)
                }
            }
        }
    }

    async fn check_chain_events(&self) -> Result<(), ChainWatcherError> {
        Ok(())
    }
}

impl HttpMockWatcher {
    fn get_merkle_root_by_epoch_inner(&self, epoch: MerkleEpoch) -> Option<MerkleRoot> {
        let merkle_root_store = self.merkle_root_store.lock().expect("not poisoned");
        merkle_root_store.get(&epoch).cloned()
    }
}
