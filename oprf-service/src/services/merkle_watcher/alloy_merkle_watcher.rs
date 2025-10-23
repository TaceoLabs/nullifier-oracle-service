use std::{collections::HashMap, sync::Arc, time::SystemTime};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent as _,
};
use async_trait::async_trait;
use eyre::Context as _;
use futures::StreamExt as _;
use oprf_types::MerkleRoot;
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::merkle_watcher::{MerkleRootStore, MerkleWatcher, MerkleWatcherError};

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        function isValidRoot(uint256 root) external view returns (bool);
        function currentRoot() external view returns (uint256);
    }
    event RootRecorded(uint256 indexed root, uint256 timestamp, uint256 indexed rootEpoch);
}

pub(crate) struct AlloyMerkleWatcher {
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl AlloyMerkleWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_merkle_store_size: usize,
    ) -> eyre::Result<Self> {
        tracing::info!("creating provider...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let contract = AccountRegistry::new(contract_address, provider.clone());

        tracing::info!("get current root...");
        let current_root = contract.currentRoot().call().await?;
        tracing::info!("root = {current_root}");

        let merkle_root_store = Arc::new(Mutex::new(
            MerkleRootStore::new(
                HashMap::from([(current_root.into(), 0)]), // insert current root with 0 timestamp so it is oldest
                max_merkle_store_size,
            )
            .context("while building merkle root store")?,
        ));
        let merkle_root_store_clone = Arc::clone(&merkle_root_store);

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RootRecorded::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        tokio::spawn(async move {
            while let Some(log) = stream.next().await {
                match RootRecorded::decode_log(log.as_ref()) {
                    Ok(event) => {
                        tracing::info!("got root {} timestamp {}", event.root, event.timestamp);
                        if let Ok(timestamp) = u64::try_from(event.timestamp) {
                            merkle_root_store_clone
                                .lock()
                                .insert(event.root.into(), timestamp);
                        } else {
                            tracing::warn!("AccountRegistry send root with timestamp > u64");
                        }
                    }
                    Err(err) => {
                        tracing::warn!("failed to decode contract event: {err:?}");
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
impl MerkleWatcher for AlloyMerkleWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn is_root_valid(&self, root: MerkleRoot) -> Result<bool, MerkleWatcherError> {
        {
            let store = self.merkle_root_store.lock();
            // first check if the merkle root is already registered
            if store.contains_root(root) {
                tracing::trace!("root was in store");
                tracing::trace!("root valid: true");
                return Ok(true);
            }
        }
        tracing::debug!("check in contract");
        let contract = AccountRegistry::new(self.contract_address, self.provider.clone());
        let valid = contract
            .isValidRoot(root.into())
            .call()
            .await
            .map_err(|err| MerkleWatcherError(err.to_string()))?;
        {
            tracing::debug!("add root to store");
            let mut store = self.merkle_root_store.lock();
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time is after unix epoch")
                .as_secs();
            store.insert(root, timestamp);
        }
        tracing::debug!("root valid: {valid}");
        return Ok(valid);
    }
}
