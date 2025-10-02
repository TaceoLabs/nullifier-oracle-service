use futures::StreamExt;
use http::StatusCode;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

use async_trait::async_trait;
use eyre::Context;
use oprf_types::{
    chain::{
        ChainEvent, SecretGenFinalizeContribution, SecretGenRound1Contribution,
        SecretGenRound2Contribution,
    },
    crypto::PartyId,
    sc_mock::{FetchRootsRequest, IsValidEpochRequest, MerkleRootUpdate, ReadEventsRequest},
};
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    config::OprfPeerConfig,
    services::chain_watcher::{
        ChainEventResult, ChainWatcher, ChainWatcherError, MerkleEpoch, MerkleRoot, MerkleRootStore,
    },
};

pub(crate) struct HttpMockWatcher {
    config: Arc<OprfPeerConfig>,
    client: reqwest::Client,
    _cancellation_token: CancellationToken,
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    _read_request: ReadEventsRequest,
}

impl HttpMockWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        party_id: PartyId,
        config: Arc<OprfPeerConfig>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        tracing::info!("spawning MOCK watcher - THIS WILL NOT TALK TO A REAL CHAIN");
        // assert that we are really in the dev environment
        config.environment.assert_is_dev();

        let client = reqwest::Client::new();
        // load a bunch of merkle roots
        let merkle_roots = client
            .get(format!("{}/api/merkle/fetch", config.chain_url))
            .query(&FetchRootsRequest {
                amount: config.max_merkle_store_size as u32,
            })
            .send()
            .await
            .context("while fetching merkle for first time")?
            .json::<Vec<MerkleRootUpdate>>()
            .await
            .context("while parsing first batch of merkle roots")?;

        let merkle_root_store = Arc::new(Mutex::new(
            MerkleRootStore::new(
                merkle_roots,
                config.max_merkle_store_size,
                config.chain_epoch_max_difference,
            )
            .context("while building merkle root store")?,
        ));

        subscribe_merkle_updates(
            &config,
            Arc::clone(&merkle_root_store),
            cancellation_token.clone(),
        )
        .await
        .context("while subscribing to merkle updates")?;
        Ok(HttpMockWatcher {
            config: Arc::clone(&config),
            _cancellation_token: cancellation_token.clone(),
            client: reqwest::Client::new(),
            merkle_root_store,
            _read_request: ReadEventsRequest { party_id },
        })
    }
}

async fn subscribe_merkle_updates(
    config: &OprfPeerConfig,
    merkle_root_store: Arc<Mutex<MerkleRootStore>>,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let subscribe_url = format!(
        "{}/api/merkle/subscribe",
        config
            .chain_url
            .replace("http", "ws")
            .replace("https", "wss")
    );
    tracing::info!("subscribing to merkle root RPC at {subscribe_url}..");
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(subscribe_url)
        .await
        .context("while subscribing to merkle root RPC")?;
    tracing::debug!("successfully subscribed!");
    tokio::task::spawn(async move {
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => match serde_json::from_str::<MerkleRootUpdate>(&text) {
                    Ok(MerkleRootUpdate { hash, epoch }) => {
                        tracing::debug!("adding new merkle root with epoch: {epoch}");
                        merkle_root_store.lock().insert(epoch, hash);
                    }
                    Err(err) => {
                        tracing::error!("cannot deserialize update from RPC: {err:?}");
                        break;
                    }
                },
                Ok(Message::Close(_)) => {
                    tracing::debug!("merkle RPC closed stream!");
                    break;
                }
                Ok(_) => {
                    tracing::error!(
                        "got unexpected msg type from RPC - only supported Text and Close"
                    );
                    break;
                }
                Err(err) => {
                    tracing::error!("error from merkle RPC: {err:?}");
                    break;
                }
            }
        }
        cancellation_token.cancel();
    });
    Ok(())
}

#[async_trait]
impl ChainWatcher for HttpMockWatcher {
    #[instrument(level = "debug", skip(self))]
    async fn get_party_id(&self) -> Result<PartyId, ChainWatcherError> {
        Ok(self._read_request.party_id)
    }

    #[instrument(level = "debug", skip(self))]
    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError> {
        tracing::trace!("checking merkle epoch: {epoch}");
        {
            let store = self.merkle_root_store.lock();
            // first check if the merkle root is already registered
            if let Some(root) = store.get_merkle_root(epoch) {
                tracing::trace!("cache hit");
                return Ok(root);
            } else {
                tracing::trace!("cache miss - check if too far in the future or past");
                store.is_sane_epoch(epoch)?;
                // is sane epoch - need to check on chain
            }
        }
        // is sane epoch - need to check on chain
        let response = self
            .client
            .get(format!("{}/api/merkle/valid", self.config.chain_url))
            .query(&IsValidEpochRequest { epoch })
            .send()
            .await
            .context("while querying epoch")?;
        let root = match response.status() {
            StatusCode::OK => response
                .text()
                .await
                .context("while reading text body")?
                .parse::<MerkleRoot>()
                .map_err(|_| eyre::eyre!("while parsing merkle root"))?,
            StatusCode::NOT_FOUND => {
                return Err(ChainWatcherError::UnknownEpoch(epoch));
            }
            // maybe we should shutdown everything here but for the mock watcher it doesn't really matter
            x => Err(eyre::eyre!("unexpected status code from chain: {x}"))?,
        };
        // we expect the update to come any minute now anyways if it is already on chain, therefore we just return and don't add
        Ok(root)
    }

    async fn check_chain_events(&self) -> Result<Vec<ChainEvent>, ChainWatcherError> {
        // Call to the mock smart contract
        Ok(self
            .client
            .get(format!("{}/api/rp/event", self.config.chain_url))
            .query(&self._read_request)
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
            .map(|r| _report_result(self.config.chain_url.clone(), self.client.clone(), r))
            .collect::<JoinSet<_>>()
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}

async fn _report_result(
    chain_url: String,
    client: reqwest::Client,
    chain_result: ChainEventResult,
) -> Result<(), ChainWatcherError> {
    match chain_result {
        ChainEventResult::SecretGenRound1(contribution) => {
            _contribute_secret_gen_round1(chain_url, client, contribution).await
        }
        ChainEventResult::SecretGenRound2(contribution) => {
            _contribute_secret_gen_round2(chain_url, client, contribution).await
        }
        ChainEventResult::SecretGenFinalize(contribution) => {
            _contribute_secret_gen_finalize(chain_url, client, contribution).await
        }
    }
}

async fn _contribute_secret_gen_round1(
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

async fn _contribute_secret_gen_round2(
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

async fn _contribute_secret_gen_finalize(
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
