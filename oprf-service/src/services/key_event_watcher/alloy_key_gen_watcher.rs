use std::{time::Duration, u64};

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{Address, Log, TxHash},
    providers::{DynProvider, PendingTransaction, Provider as _, ProviderBuilder, WsConnect},
    pubsub::Subscription,
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use async_trait::async_trait;
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    RpId,
    chain::{
        ChainEvent, ChainEventResult, SecretGenRound1Contribution, SecretGenRound1Event,
        SecretGenRound2Contribution, SecretGenRound2Event,
    },
    crypto::{PartyId, PeerPublicKey, PeerPublicKeyList},
};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::services::key_event_watcher::KeyGenEventListener;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    KeyGenContract,
    "../contracts/abi.json"
);

pub(crate) struct AlloyKeyGenWatcher {
    contract_address: Address,
    provider: DynProvider,
}

impl AlloyKeyGenWatcher {
    pub(crate) async fn init(
        rpc_url: &str,
        address: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        // Create the provider.
        let ws = WsConnect::new(rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?;

        Ok(Self {
            provider: provider.erased(),
            contract_address: address,
        })
    }
}
#[async_trait]
impl KeyGenEventListener for AlloyKeyGenWatcher {
    async fn fetch_party_id(&self) -> eyre::Result<PartyId> {
        let contract = KeyGenContract::new(self.contract_address, self.provider.clone());
        let my_id = contract
            .getMyId()
            .call()
            .await
            .context("while fetching party ID from chain")?;
        let party_id = u16::try_from(my_id).map_err(|_| eyre::eyre!("got partyID > 65536"))?;
        Ok(PartyId::from(party_id))
    }

    async fn subscribe(&self) -> eyre::Result<mpsc::Receiver<ChainEvent>> {
        // Mailbox size of 1 is enough, because we only have on consumer
        // and it will handle events sequentially.
        let (tx, rx) = mpsc::channel(1);
        let provider = self.provider.clone();
        let address = self.contract_address;
        tokio::spawn(async move {
            match subscribe_task(provider, address, tx).await {
                Ok(_) => tracing::info!("subscribe task shutdown"),
                Err(err) => tracing::error!("subscribe task encountered an error: {err}"),
            }
        });
        Ok(rx)
    }
    async fn report_result(&self, result: ChainEventResult) -> eyre::Result<()> {
        let contract = KeyGenContract::new(self.contract_address, self.provider.clone());
        match result {
            ChainEventResult::SecretGenRound1(SecretGenRound1Contribution {
                rp_id,
                sender: _,
                contribution,
            }) => {
                let contribution =
                    bincode::serde::encode_to_vec(&contribution, bincode::config::standard())
                        .expect("can serialize");
                let receipt = contract
                    .addRound1Contribution(rp_id.into_inner(), contribution.into())
                    .gas(1000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .with_required_confirmations(2)
                    .with_timeout(Some(Duration::from_secs(60)))
                    .get_receipt()
                    .await
                    .context("while waiting for receipt")?;
                if receipt.status() {
                    tracing::info!("done with transaction hash: {}", receipt.transaction_hash);
                } else {
                    eyre::bail!("could not post contribution1 to chain: {receipt:?}");
                }
            }
            ChainEventResult::SecretGenRound2(SecretGenRound2Contribution {
                rp_id,
                sender: _,
                contribution,
            }) => {
                let contribution =
                    bincode::serde::encode_to_vec(&contribution, bincode::config::standard())
                        .expect("can serialize");
                let receipt = contract
                    .addRound2Contribution(rp_id.into_inner(), contribution.into())
                    .gas(1000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .with_required_confirmations(2)
                    .with_timeout(Some(Duration::from_secs(60)))
                    .get_receipt()
                    .await
                    .context("while waiting for receipt")?;
                if receipt.status() {
                    tracing::info!("done with transaction hash: {}", receipt.transaction_hash);
                } else {
                    eyre::bail!("could not post contribution1 to chain: {receipt:?}");
                }
                todo!()
            }
            ChainEventResult::SecretGenFinalize(contribution) => todo!(),
        };
        Ok(())
    }
}

async fn subscribe_task(
    provider: DynProvider,
    contract_address: Address,
    tx: mpsc::Sender<ChainEvent>,
) -> eyre::Result<()> {
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest);
    // Subscribe to event logs
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        match log.topic0() {
            Some(&KeyGenContract::SecretGenRound1::SIGNATURE_HASH) => {
                let round1 = log
                    .log_decode()
                    .context("while decoding secret-gen round1 event")?;
                let KeyGenContract::SecretGenRound1 { rpId, degree } = round1.inner.data;

                let event = ChainEvent::SecretGenRound1(SecretGenRound1Event {
                    rp_id: RpId::from(rpId),
                    degree,
                });

                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            Some(&KeyGenContract::SecretGenRound2::SIGNATURE_HASH) => {
                let round2 = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let KeyGenContract::SecretGenRound2 {
                    rpId,
                    peerPublicKeyList,
                } = round2.inner.data;
                tracing::info!("str: {peerPublicKeyList}");
                let public_key_bytes = Vec::<u8>::from(peerPublicKeyList);
                let (pub_keys, _) = bincode::serde::decode_from_slice::<PeerPublicKeyList, _>(
                    &public_key_bytes,
                    bincode::config::standard(),
                )
                .context("while deserializing PeerPublicKeyList")?;
                let event = ChainEvent::SecretGenRound2(SecretGenRound2Event {
                    rp_id: RpId::from(rpId),
                    keys: pub_keys,
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }

            Some(&KeyGenContract::SecretGenFinalize::SIGNATURE_HASH) => {
                tracing::info!("i have finalaize uwu");
                let finalize = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let KeyGenContract::SecretGenFinalize {
                    rpId,
                    rpPublicKey,
                    round2Contributions,
                } = finalize.inner.data;

                let bytes = Vec::<u8>::from(round2Contributions);
            }
            _ => todo!(),
        }
    }
    Ok(())
}
