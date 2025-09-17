use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use eyre::Context;
use oprf_types::{
    chain::{
        ChainEvent, SecretGenFinalizeContribution, SecretGenRound1Contribution,
        SecretGenRound2Contribution,
    },
    sc_mock::ReadEventsRequest,
};
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    config::OprfPeerConfig,
    services::{
        chain_watcher::{
            ChainEventResult, ChainWatcher, ChainWatcherError, ChainWatcherService, MerkleEpoch,
            MerkleRoot,
        },
        crypto_device::CryptoDevice,
    },
};

type MerkleRootStore = HashMap<MerkleEpoch, MerkleRoot>;

struct HttpMockWatcher {
    config: Arc<OprfPeerConfig>,
    client: reqwest::Client,
    _cancellation_token: CancellationToken,
    _merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    read_request: ReadEventsRequest,
}

#[instrument(level = "info", skip_all)]
pub(crate) fn init(
    config: Arc<OprfPeerConfig>,
    crypto_device: Arc<CryptoDevice>,
    cancellation_token: CancellationToken,
) -> ChainWatcherService {
    tracing::info!("spawning MOCK watcher - THIS WILL NOT TALK TO A REAL CHAIN");
    // assert that we are really in the dev environment
    config.environment.assert_is_dev();
    let merkle_root_store = Arc::new(Mutex::new(MerkleRootStore::new()));
    Arc::new(HttpMockWatcher {
        config: Arc::clone(&config),
        _cancellation_token: cancellation_token.clone(),
        client: reqwest::Client::new(),
        _merkle_root_store: merkle_root_store,
        read_request: ReadEventsRequest {
            key: crypto_device.oprf_identifier(),
        },
    })
}

#[async_trait]
impl ChainWatcher for HttpMockWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn get_merkle_root_by_epoch(
        &self,
        _epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError> {
        // TODO this must work with tungstenite
        todo!()
    }

    async fn check_chain_events(&self) -> Result<Vec<ChainEvent>, ChainWatcherError> {
        // Call to the mock smart contract
        Ok(self
            .client
            .get(format!("{}/api/rp/event", self.config.chain_url))
            .query(&self.read_request)
            .send()
            .await
            .context("while send request")?
            .json::<Vec<ChainEvent>>()
            .await
            .context("while deserializing chain events")?)
    }

    async fn report_chain_results(
        &self,
        results: Vec<ChainEventResult>,
    ) -> Result<(), ChainWatcherError> {
        results
            .into_iter()
            .map(|r| report_result(self.config.chain_url.clone(), self.client.clone(), r))
            .collect::<JoinSet<_>>()
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}

async fn report_result(
    chain_url: String,
    client: reqwest::Client,
    chain_result: ChainEventResult,
) -> Result<(), ChainWatcherError> {
    match chain_result {
        ChainEventResult::SecretGenRound1(contribution) => {
            contribute_secret_gen_round1(chain_url, client, contribution).await
        }
        ChainEventResult::SecretGenRound2(contribution) => {
            contribute_secret_gen_round2(chain_url, client, contribution).await
        }
        ChainEventResult::SecretGenFinalize(contribution) => {
            contribute_secret_gen_finalize(chain_url, client, contribution).await
        }
    }
}

async fn contribute_secret_gen_round1(
    chain_url: String,
    client: reqwest::Client,
    contribution: SecretGenRound1Contribution,
) -> Result<(), ChainWatcherError> {
    tracing::info!("posting round1 contribution for {}", contribution.rp_id);
    client
        .post(format!("{chain_url}/api/rp/keygen/round1"))
        .json(&contribution)
        .send()
        .await
        .context("while send request")?
        .error_for_status()
        .context("while checking status code")?;
    Ok(())
}

async fn contribute_secret_gen_round2(
    chain_url: String,
    client: reqwest::Client,
    contribution: SecretGenRound2Contribution,
) -> Result<(), ChainWatcherError> {
    tracing::info!("posting round2 contribution for {}", contribution.rp_id);
    client
        .post(format!("{chain_url}/api/rp/keygen/round2"))
        .json(&contribution)
        .send()
        .await
        .context("while send request")?
        .error_for_status()
        .context("while checking status code")?;
    Ok(())
}

async fn contribute_secret_gen_finalize(
    chain_url: String,
    client: reqwest::Client,
    contribution: SecretGenFinalizeContribution,
) -> Result<(), ChainWatcherError> {
    tracing::info!("posting finalize contribution for {}", contribution.rp_id);
    client
        .post(format!("{chain_url}/api/rp/keygen/finalize"))
        .json(&contribution)
        .send()
        .await
        .context("while send request")?
        .error_for_status()
        .context("while checking status code")?;
    Ok(())
}
