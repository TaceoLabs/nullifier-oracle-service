use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{Address, TxHash},
    providers::{DynProvider, PendingTransaction, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::{Filter, TransactionReceipt},
    sol,
    sol_types::SolEvent,
    transports::RpcError,
};
use async_trait::async_trait;
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    RpId,
    chain::{
        ChainEvent, ChainEventResult, SecretGenFinalizeContribution, SecretGenFinalizeEvent,
        SecretGenRound1Contribution, SecretGenRound1Event, SecretGenRound2Contribution,
        SecretGenRound2Event,
    },
    crypto::{PartyId, PeerPublicKeyList, RpSecretGenCiphertexts},
};
use tokio::sync::mpsc;

use crate::services::key_event_watcher::KeyGenEventListener;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    KeyGenContract,
    "../contracts/abi.json"
);

pub(crate) struct AlloyKeyGenWatcher {
    party_id: PartyId,
    contract_address: Address,
    provider: DynProvider,
}

impl AlloyKeyGenWatcher {
    pub(crate) async fn init(
        rpc_url: &str,
        contract_address: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        // Create the provider.
        let ws = WsConnect::new(rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?;

        let contract = KeyGenContract::new(contract_address, provider.clone());
        let party_id = contract
            .getMyId()
            .call()
            .await
            .context("while fetching party ID from chain")?;
        let party_id = u16::try_from(party_id).map_err(|_| eyre::eyre!("got partyID > 65536"))?;

        Ok(Self {
            party_id: PartyId::from(party_id),
            provider: provider.erased(),
            contract_address,
        })
    }
}
#[async_trait]
impl KeyGenEventListener for AlloyKeyGenWatcher {
    async fn fetch_party_id(&self) -> eyre::Result<PartyId> {
        Ok(self.party_id)
    }

    async fn subscribe(&self) -> eyre::Result<mpsc::Receiver<ChainEvent>> {
        // Mailbox size of 1 is enough, because we only have on consumer
        // and it will handle events sequentially.
        let (tx, rx) = mpsc::channel(1);
        let provider = self.provider.clone();
        let address = self.contract_address;
        let party_id = self.party_id;
        tokio::spawn(async move {
            match subscribe_task(party_id, provider, address, tx).await {
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
                let pending_tx = contract
                    .addRound1Contribution(rp_id.into_inner(), contribution.into())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .register()
                    .await
                    .context("while registering watcher for transaction")?;
                let (receipt, tx_hash) = watch_receipt(self.provider.clone(), pending_tx)
                    .await
                    .context("while waiting for receipt")?;
                if receipt.status() {
                    tracing::info!("round 1 done with transaction hash: {tx_hash}",);
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
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
                let pending_tx = contract
                    .addRound2Contribution(rp_id.into_inner(), contribution.into())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .register()
                    .await
                    .context("while registering watcher for transaction")?;
                let (receipt, tx_hash) = watch_receipt(self.provider.clone(), pending_tx)
                    .await
                    .context("while waiting for receipt")?;
                if receipt.status() {
                    tracing::info!("round 2 done with transaction hash: {tx_hash}",);
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
            ChainEventResult::SecretGenFinalize(SecretGenFinalizeContribution {
                rp_id,
                sender: _,
            }) => {
                let pending_tx = contract
                    .addFinalizeContribtion(rp_id.into_inner())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .register()
                    .await
                    .context("while registering watcher for transaction")?;
                let (receipt, tx_hash) = watch_receipt(self.provider.clone(), pending_tx)
                    .await
                    .context("while waiting for receipt")?;
                if receipt.status() {
                    tracing::info!("finalize done with transaction hash: {tx_hash}",);
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
        };
        Ok(())
    }
}

async fn subscribe_task(
    party_id: PartyId,
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
                let finalize = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let KeyGenContract::SecretGenFinalize {
                    rpId,
                    rpPublicKey,
                    round2Contributions,
                } = finalize.inner.data;

                let ciphers = round2Contributions
                    .into_iter()
                    .map(|ciphers| {
                        let (x, _) = bincode::serde::decode_from_slice(
                            &ciphers.data,
                            bincode::config::standard(),
                        )?;
                        eyre::Ok(x)
                    })
                    .collect::<eyre::Result<Vec<RpSecretGenCiphertexts>>>()?;
                // filter so that I can find my ciphers
                let ciphers = ciphers
                    .into_iter()
                    .filter_map(|cipher| cipher.get_cipher_text(party_id))
                    .collect::<Vec<_>>();
                let rp_verification_key = Vec::<u8>::from(rpPublicKey);
                let (rp_public_key, _) = bincode::serde::decode_from_slice(
                    &rp_verification_key,
                    bincode::config::standard(),
                )
                .context("while parsing verification key")?;

                let event = ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
                    rp_id: RpId::from(rpId),
                    rp_public_key,
                    ciphers,
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            x => {
                tracing::info!("unknown event: {x:?}");
            }
        }
    }
    Ok(())
}

async fn watch_receipt(
    provider: DynProvider,
    mut pending_tx: PendingTransaction,
) -> Result<(TransactionReceipt, TxHash), alloy::contract::Error> {
    let tx_hash = pending_tx.tx_hash().to_owned();
    // FIXME: this is a hotfix to prevent a race condition where the heartbeat would miss the
    // block the tx was mined in

    let mut interval = tokio::time::interval(provider.client().poll_interval());

    loop {
        let mut confirmed = false;

        tokio::select! {
            _ = interval.tick() => {},
            res = &mut pending_tx => {
                let _ = res?;
                confirmed = true;
            }
        }

        // try to fetch the receipt
        if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
            return Ok((receipt, tx_hash));
        }

        if confirmed {
            return Err(alloy::contract::Error::TransportError(RpcError::NullResp));
        }
    }
}
