use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, TxHash},
    providers::{DynProvider, PendingTransaction, Provider as _},
    rpc::types::{Filter, TransactionReceipt},
    sol_types::SolEvent,
    transports::RpcError,
};
use async_trait::async_trait;
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    RpId,
    chain::{
        ChainEvent, ChainEventResult, SecretGenFinalizeEvent, SecretGenRound1Contribution,
        SecretGenRound1Event, SecretGenRound2Contribution, SecretGenRound2Event,
        SecretGenRound3Contribution, SecretGenRound3Event,
    },
    crypto::{RpNullifierKey, RpSecretGenCiphertext},
};
use tokio::sync::mpsc;

use crate::{rp_registry::KeyGen, services::key_event_watcher::KeyGenEventListener};

pub(crate) struct AlloyKeyGenWatcher {
    contract_address: Address,
    provider: DynProvider,
}

impl AlloyKeyGenWatcher {
    pub(crate) fn new(contract_address: Address, provider: DynProvider) -> Self {
        Self {
            contract_address,
            provider,
        }
    }
}

#[async_trait]
impl KeyGenEventListener for AlloyKeyGenWatcher {
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
        let contract = KeyGen::new(self.contract_address, self.provider.clone());
        match result {
            ChainEventResult::SecretGenRound1(SecretGenRound1Contribution {
                rp_id,
                contribution,
            }) => {
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
                contribution,
            }) => {
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
            ChainEventResult::SecretGenRound3(SecretGenRound3Contribution { rp_id }) => {
                let pending_tx = contract
                    .addRound3Contribution(rp_id.into_inner())
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
                    tracing::info!("round3 done with transaction hash: {tx_hash}",);
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
            ChainEventResult::NothingToReport => (),
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
    let contract = KeyGen::new(contract_address, provider.clone());
    // Subscribe to event logs
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        match log.topic0() {
            Some(&KeyGen::SecretGenRound1::SIGNATURE_HASH) => {
                let round1 = log
                    .log_decode()
                    .context("while decoding secret-gen round1 event")?;
                let KeyGen::SecretGenRound1 { rpId, threshold } = round1.inner.data;
                let event = ChainEvent::SecretGenRound1(SecretGenRound1Event {
                    rp_id: RpId::from(rpId),
                    threshold: u16::try_from(threshold)?,
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            Some(&KeyGen::SecretGenRound2::SIGNATURE_HASH) => {
                tracing::debug!("got round 2 event!");
                let round2 = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let KeyGen::SecretGenRound2 { rpId } = round2.inner.data;
                let event = ChainEvent::SecretGenRound2(SecretGenRound2Event {
                    rp_id: RpId::from(rpId),
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            Some(&KeyGen::SecretGenRound3::SIGNATURE_HASH) => {
                tracing::debug!("got round 3 event!");
                let round3 = log
                    .log_decode()
                    .context("while decoding secret-gen round3 event")?;
                let KeyGen::SecretGenRound3 { rpId } = round3.inner.data;
                let ciphers = contract
                    .checkIsParticipantAndReturnRound2Ciphers(rpId)
                    .call()
                    .await?;
                let event = ChainEvent::SecretGenRound3(SecretGenRound3Event {
                    rp_id: RpId::from(rpId),
                    ciphers: ciphers
                        .into_iter()
                        .map(RpSecretGenCiphertext::try_from)
                        .collect::<eyre::Result<Vec<_>>>()?,
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            Some(&KeyGen::SecretGenFinalize::SIGNATURE_HASH) => {
                let finalize = log
                    .log_decode()
                    .context("while decoding secret-gen finalize event")?;
                let KeyGen::SecretGenFinalize { rpId } = finalize.inner.data;
                let rp_material = contract.getRpMaterial(rpId).call().await?;
                let event = ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
                    rp_id: RpId::from(rpId),
                    rp_public_key: rp_material.ecdsaKey.try_into()?,
                    rp_nullifier_key: RpNullifierKey::new(rp_material.nullifierKey.try_into()?),
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
