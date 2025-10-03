use std::sync::Arc;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent as _,
};
use async_trait::async_trait;
use eyre::Context as _;
use futures::StreamExt as _;
use oprf_types::{MerkleEpoch, MerkleRoot};
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::merkle_watcher::{MerkleRootStore, MerkleWatcher, MerkleWatcherError};

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        function isValidRoot(uint256 root) external view returns (bool);
    }
    event RootRecorded(uint256 indexed root, uint256 timestamp, uint256 indexed rootEpoch);
}

pub(crate) struct RealMerkleWatcher {
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl RealMerkleWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_merkle_store_size: usize,
        chain_epoch_max_difference: u128,
    ) -> eyre::Result<Self> {
        tracing::info!("creating provider...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

        let merkle_root_store = Arc::new(Mutex::new(
            MerkleRootStore::new(
                Vec::new(),
                max_merkle_store_size,
                chain_epoch_max_difference,
            )
            .context("while building merkle root store")?,
        ));
        let merkle_root_store_clone = Arc::clone(&merkle_root_store);

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .event_signature(RootRecorded::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        tokio::spawn(async move {
            while let Some(log) = stream.next().await {
                match RootRecorded::decode_log(log.as_ref()) {
                    Ok(event) => {
                        tracing::info!("got epoch {} root {}", event.rootEpoch, event.root);
                        merkle_root_store_clone
                            .lock()
                            .insert(event.rootEpoch.into(), event.root.into());
                    }
                    Err(err) => {
                        tracing::info!("failed to decode contract event: {err:?}");
                    }
                }
            }
        });

        Ok(Self {
            merkle_root_store,
            provider: provider.erased(),
            contract_address,
        })
    }
}

#[async_trait]
impl MerkleWatcher for RealMerkleWatcher {
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
            }
        }
        // TODO is it fine to reconstruct this every time?
        let contract = AccountRegistry::new(self.contract_address, self.provider.clone());
        let valid = contract
            .isValidRoot(root.into())
            .call()
            .await
            .map_err(|err| MerkleWatcherError::ChainCommunicationError(eyre::eyre!("{err:?}")))?;
        tracing::debug!("root valid: {valid}");
        return Ok(valid);
    }
}
