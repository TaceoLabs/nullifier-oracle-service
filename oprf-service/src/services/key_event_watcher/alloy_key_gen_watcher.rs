//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`AlloyKeyGenWatcher`], an implementation of [`KeyGenEventListener`]
//! that monitors an on-chain RpRegistry contract for key generation events.
//!
//! The watcher subscribes to various key generation events (Round 1, 2, 3, and Finalize)
//! and reports contributions back to the contract. It uses Alloy for blockchain interaction.

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{Address, TxHash},
    providers::{DynProvider, PendingTransaction, Provider as _, ProviderBuilder, WsConnect},
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
    crypto::{PartyId, PeerPublicKey, PeerPublicKeyList, RpNullifierKey, RpSecretGenCiphertext},
};
use tokio::sync::mpsc;

use crate::{rp_registry::RpRegistry, services::key_event_watcher::KeyGenEventListener};

/// Monitors key generation events from an on-chain RpRegistry contract.
///
/// Subscribes to blockchain events for key generation rounds and reports
/// contributions back to the contract.
pub(crate) struct AlloyKeyGenWatcher {
    contract_address: Address,
    provider: DynProvider,
}

impl AlloyKeyGenWatcher {
    /// Creates a new key generation event watcher.
    ///
    /// Connects to the blockchain via WebSocket and verifies that the
    /// RpRegistry contract is ready.
    ///
    /// # Arguments
    /// * `rpc_url` - WebSocket RPC URL for blockchain connection
    /// * `contract_address` - Address of the RpRegistry contract
    /// * `wallet` - Ethereum wallet for signing transactions
    pub(crate) async fn new(
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
        tracing::info!("checking RpRegistry ready state at address {contract_address}..");
        let contract = RpRegistry::new(contract_address, provider.clone());
        if !contract.isContractReady().call().await? {
            eyre::bail!("RpRegistry contract not ready");
        }
        tracing::info!("ready!");
        Ok(Self {
            contract_address,
            provider: provider.erased(),
        })
    }
}

#[async_trait]
impl KeyGenEventListener for AlloyKeyGenWatcher {
    async fn subscribe(&self) -> eyre::Result<mpsc::Receiver<ChainEvent>> {
        // mailbox size of 8 is fairly arbitrary
        let (tx, rx) = mpsc::channel(8);
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
        let contract = RpRegistry::new(self.contract_address, self.provider.clone());
        match result {
            ChainEventResult::SecretGenRound1(SecretGenRound1Contribution {
                rp_id,
                contribution,
            }) => {
                let receipt = contract
                    .addRound1Contribution(rp_id.into_inner(), contribution.into())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .get_receipt()
                    .await
                    .context("while registering watcher for transaction")?;
                if receipt.status() {
                    tracing::info!(
                        "round 1 done with transaction hash: {}",
                        receipt.transaction_hash
                    );
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
            ChainEventResult::SecretGenRound2(SecretGenRound2Contribution {
                rp_id,
                contribution,
            }) => {
                let receipt = contract
                    .addRound2Contribution(rp_id.into_inner(), contribution.into())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .get_receipt()
                    .await
                    .context("while registering watcher for transaction")?;
                if receipt.status() {
                    tracing::info!(
                        "round 2 done with transaction hash: {}",
                        receipt.transaction_hash
                    );
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
            ChainEventResult::SecretGenRound3(SecretGenRound3Contribution { rp_id }) => {
                let receipt = contract
                    .addRound3Contribution(rp_id.into_inner())
                    .gas(10000000) // FIXME this is only for dummy smart contract
                    .send()
                    .await
                    .context("while broadcasting to network")?
                    .get_receipt()
                    .await
                    .context("while registering watcher for transaction")?;
                if receipt.status() {
                    tracing::info!(
                        "round3 done with transaction hash: {}",
                        receipt.transaction_hash
                    );
                } else {
                    eyre::bail!("cannot finish transaction: {receipt:?}");
                }
            }
        };
        Ok(())
    }

    /// Loads the party ID for this peer from the RpRegistry contract.
    async fn load_party_id(&self) -> eyre::Result<PartyId> {
        let contract = RpRegistry::new(self.contract_address, self.provider.clone());
        let party_id = contract.checkIsParticipantAndReturnPartyId().call().await?;
        Ok(PartyId(u16::try_from(party_id)?))
    }
}

/// Background task that subscribes to key generation events.
///
/// Filters for various key generation event signatures and sends them
/// to the provided channel.
async fn subscribe_task(
    provider: DynProvider,
    contract_address: Address,
    tx: mpsc::Sender<ChainEvent>,
) -> eyre::Result<()> {
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest)
        .event_signature(vec![
            RpRegistry::SecretGenRound1::SIGNATURE_HASH,
            RpRegistry::SecretGenRound2::SIGNATURE_HASH,
            RpRegistry::SecretGenRound3::SIGNATURE_HASH,
            RpRegistry::SecretGenFinalize::SIGNATURE_HASH,
            RpRegistry::KeyDeletion::SIGNATURE_HASH,
        ]);
    // Subscribe to event logs
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    while let Some(log) = stream.next().await {
        match log.topic0() {
            Some(&RpRegistry::SecretGenRound1::SIGNATURE_HASH) => {
                let round1 = log
                    .log_decode()
                    .context("while decoding secret-gen round1 event")?;
                let RpRegistry::SecretGenRound1 { rpId, threshold } = round1.inner.data;
                let event = ChainEvent::SecretGenRound1(SecretGenRound1Event {
                    rp_id: RpId::from(rpId),
                    threshold: u16::try_from(threshold)?,
                });
                if tx.send(event).await.is_err() {
                    tracing::debug!("subscriber dropped channel - will shutdown");
                    break;
                }
            }
            Some(&RpRegistry::SecretGenRound2::SIGNATURE_HASH) => {
                tracing::debug!("got round 2 event!");
                let round2 = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let RpRegistry::SecretGenRound2 { rpId } = round2.inner.data;
                let event = prepare_round2_event(rpId, contract_address, provider.clone())
                    .await
                    .context("while preparing round2 event");
                match event {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            tracing::debug!("subscriber dropped channel - will shutdown");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("could not prepare round2 event: {err:?}");
                        tracing::warn!("try fetching next event");
                    }
                }
            }
            Some(&RpRegistry::SecretGenRound3::SIGNATURE_HASH) => {
                tracing::debug!("got round 3 event!");
                let round3 = log
                    .log_decode()
                    .context("while decoding secret-gen round3 event")?;
                let RpRegistry::SecretGenRound3 { rpId } = round3.inner.data;
                let event = prepare_round3_event(rpId, contract_address, provider.clone())
                    .await
                    .context("while preparing round3 event");
                match event {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            tracing::debug!("subscriber dropped channel - will shutdown");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("could not prepare round3 event: {err:?}");
                        tracing::warn!("try fetching next event");
                    }
                }
            }
            Some(&RpRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
                let finalize = log
                    .log_decode()
                    .context("while decoding secret-gen finalize event")?;
                let RpRegistry::SecretGenFinalize { rpId } = finalize.inner.data;
                let event = prepare_finalize_event(rpId, contract_address, provider.clone())
                    .await
                    .context("while preparing finalize event");
                match event {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            tracing::debug!("subscriber dropped channel - will shutdown");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("could not prepare finalize event: {err:?}");
                        tracing::warn!("try fetching next event");
                    }
                }
            }

            Some(&RpRegistry::KeyDeletion::SIGNATURE_HASH) => {
                let key_delete = log
                    .log_decode()
                    .context("while decoding key deletion event")?;
                let RpRegistry::KeyDeletion { rpId } = key_delete.inner.data;
                tracing::info!("got key deletion event for {rpId}");
                let event = ChainEvent::DeleteRpMaterial(RpId::from(rpId));
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

/// Watches for a transaction receipt with improved polling.
///
/// Polls the blockchain at regular intervals to fetch the transaction receipt,
/// working around potential race conditions with block confirmations.
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

/// Prepares a Round 2 event by fetching ephemeral public keys from the contract.
///
/// Queries the RpRegistry contract to retrieve the ephemeral public keys
/// submitted by all peers in Round 1.
async fn prepare_round2_event(
    rp_id: u128,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<ChainEvent> {
    let contract = RpRegistry::new(contract_address, provider.clone());
    let peers = contract
        .checkIsParticipantAndReturnEphemeralPublicKeys(rp_id)
        .call()
        .await
        .context("while loading eph keys")?;
    // TODO handle error case better - we want to know which one send wrong key
    let list = peers
        .into_iter()
        .map(PeerPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    let event = ChainEvent::SecretGenRound2(SecretGenRound2Event {
        rp_id: RpId::from(rp_id),
        peers: PeerPublicKeyList::from(list),
    });
    Ok(event)
}

/// Prepares a Round 3 event by fetching ciphertexts from the contract.
///
/// Queries the RpRegistry contract to retrieve the ciphertexts
/// submitted by all peers in Round 2.
async fn prepare_round3_event(
    rp_id: u128,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<ChainEvent> {
    let contract = RpRegistry::new(contract_address, provider.clone());
    let ciphers = contract
        .checkIsParticipantAndReturnRound2Ciphers(rp_id)
        .call()
        .await
        .context("while loading ciphers")?;
    let event = ChainEvent::SecretGenRound3(SecretGenRound3Event {
        rp_id: RpId::from(rp_id),
        ciphers: ciphers
            .into_iter()
            .map(RpSecretGenCiphertext::try_from)
            .collect::<eyre::Result<Vec<_>>>()?,
    });
    Ok(event)
}

/// Prepares a finalize event by fetching RP material from the contract.
///
/// Queries the RpRegistry contract to retrieve the final RP material
/// including the public key and nullifier key.
async fn prepare_finalize_event(
    rp_id: u128,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<ChainEvent> {
    let contract = RpRegistry::new(contract_address, provider.clone());
    let rp_material = contract.getRpMaterial(rp_id).call().await?;
    let event = ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
        rp_id: RpId::from(rp_id),
        rp_public_key: rp_material.ecdsaKey.try_into()?,
        rp_nullifier_key: RpNullifierKey::new(rp_material.nullifierKey.try_into()?),
    });
    Ok(event)
}
