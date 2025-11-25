//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to monitor an on-chain OprfKeyRegistry contract for key generation events.
//!
//! The watcher subscribes to various key generation events and reports contributions back to the contract.

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, LogData},
    providers::{DynProvider, Provider as _},
    rpc::types::{Filter, Log},
    sol_types::SolEvent as _,
};
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    OprfKeyId,
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    oprf_key_registry::OprfKeyRegistry::{self, OprfKeyRegistryInstance},
    services::{secret_gen::DLogSecretGenService, secret_manager::SecretManagerService},
};

/// Background task that subscribes to key generation events and handles them.
///
/// Connects to the blockchain via WebSocket and verifies that the
/// `OprfKeyRegistry` contract is ready.
pub(crate) async fn key_event_watcher_task(
    provider: DynProvider,
    contract_address: Address,
    secret_manager: SecretManagerService,
    dlog_secret_gen_service: DLogSecretGenService,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    // shutdown service if event watcher encounters an error and drops this guard
    let _drop_guard = cancellation_token.drop_guard_ref();
    tracing::info!("checking OprfKeyRegistry ready state at address {contract_address}..");
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    if !contract.isContractReady().call().await? {
        eyre::bail!("OprfKeyRegistry contract not ready");
    }
    tracing::info!("ready!");

    tracing::info!("start handling events");
    match handle_events(
        provider,
        contract_address,
        dlog_secret_gen_service,
        secret_manager,
        cancellation_token.clone(),
    )
    .await
    {
        Ok(_) => tracing::info!("stopped key event watcher"),
        Err(err) => tracing::error!("key event watcher encountered an error: {err}"),
    }
    Ok(())
}

/// Filters for various key generation event signatures and handles them
async fn handle_events(
    provider: DynProvider,
    contract_address: Address,
    mut secret_gen: DLogSecretGenService,
    secret_manager: SecretManagerService,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    let filter = Filter::new()
        .address(contract_address)
        .from_block(BlockNumberOrTag::Latest)
        .event_signature(vec![
            OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH,
            OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH,
            OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH,
            OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH,
            OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH,
        ]);
    // Subscribe to event logs
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();
    loop {
        let log = tokio::select! {
            log = stream.next() => {
                log.ok_or_else(||eyre::eyre!("logs subscribe stream was closed"))?
            }
            _ = cancellation_token.cancelled() => {
                break;
            }
        };

        match log.topic0() {
            Some(&OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH) => {
                handle_round1(log, &contract, &mut secret_gen)
                    .await
                    .context("while handling round1")?
            }
            Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
                handle_round2(log, &contract, &mut secret_gen)
                    .await
                    .context("while handling round2")?
            }
            Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
                handle_round3(log, &contract, &mut secret_gen)
                    .await
                    .context("while handling round3")?
            }
            Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
                handle_finalize(log, &contract, &mut secret_gen, &secret_manager)
                    .await
                    .context("while handling finalize")?
            }

            Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
                handle_delete(log, &mut secret_gen, &secret_manager)
                    .await
                    .context("while handling deletion")?
            }
            x => {
                tracing::warn!("unknown event: {x:?}");
            }
        }
    }
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_round1(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound1 event");
    let log = log
        .log_decode()
        .context("while decoding secret-gen round1 event")?;
    let OprfKeyRegistry::SecretGenRound1 {
        oprfKeyId,
        threshold,
    } = log.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId} with threshold {threshold}");

    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let threshold = u16::try_from(threshold)?;

    let res = secret_gen.round1(oprf_key_id, threshold);
    tracing::debug!("finished round1 - now reporting to chain..");
    let receipt = contract
        .addRound1Contribution(res.oprf_key_id.into_inner(), res.contribution.into())
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
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_round2(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound2 event");
    let round2 = log
        .log_decode()
        .context("while decoding secret-gen round2 event")?;
    let OprfKeyRegistry::SecretGenRound2 { oprfKeyId } = round2.inner.data;
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("fetching ephemeral public keys from chain..");
    let peers = contract
        .checkIsParticipantAndReturnEphemeralPublicKeys(oprfKeyId)
        .call()
        .await
        .context("while loading eph keys")?;
    tracing::debug!("got keys from chain - parsing..");
    // TODO handle error case better - we want to know which one send wrong key
    let peers = peers
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId}");
    // block_in_place here because we do a lot CPU work
    let res = tokio::task::block_in_place(|| {
        secret_gen
            .round2(oprf_key_id, peers.into())
            .context("while doing round2")
    })?;
    tracing::debug!("finished round 2 - now reporting");
    let receipt = contract
        .addRound2Contribution(res.oprf_key_id.into_inner(), res.contribution.into())
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
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_round3(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenRound3 event");
    let round3 = log
        .log_decode()
        .context("while decoding secret-gen round3 event")?;
    let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = round3.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId}");
    let oprf_key_id = OprfKeyId::from(oprfKeyId);

    tracing::info!("reading ciphers from chain..");
    let ciphers = contract
        .checkIsParticipantAndReturnRound2Ciphers(oprfKeyId)
        .call()
        .await
        .context("while loading ciphers")?;
    tracing::debug!("got ciphers from chain - parsing..");
    let ciphers = ciphers
        .into_iter()
        .map(SecretGenCiphertext::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    let res = secret_gen
        .round3(oprf_key_id, ciphers)
        .context("while doing round3")?;
    tracing::debug!("finished round 3 - now reporting");
    let receipt = contract
        .addRound3Contribution(res.oprf_key_id.into_inner())
        .gas(10000000) // FIXME this is only for dummy smart contract
        .send()
        .await
        .context("while broadcasting to network")?
        .get_receipt()
        .await
        .context("while registering watcher for transaction")?;
    if receipt.status() {
        tracing::info!(
            "round 3 done with transaction hash: {}",
            receipt.transaction_hash
        );
    } else {
        eyre::bail!("cannot finish transaction: {receipt:?}");
    }
    Ok(())
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_finalize(
    log: Log<LogData>,
    contract: &OprfKeyRegistryInstance<DynProvider>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
) -> eyre::Result<()> {
    tracing::info!("Received SecretGenFinalize event");
    let finalize = log
        .log_decode()
        .context("while decoding secret-gen finalize event")?;
    let OprfKeyRegistry::SecretGenFinalize { oprfKeyId } = finalize.inner.data;
    let handle_span = tracing::Span::current();
    handle_span.record("oprf_key_id", oprfKeyId.to_string());
    tracing::info!("Event for {oprfKeyId}");
    let oprf_public_key = contract.getOprfPublicKey(oprfKeyId).call().await?;
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    let oprf_public_key = OprfPublicKey::new(oprf_public_key.try_into()?);
    let store_dlog_share = secret_gen
        .finalize(oprf_key_id, oprf_public_key)
        .context("while finalizing secret-gen")?;
    secret_manager
        .store_dlog_share(store_dlog_share)
        .await
        .context("while storing share to secret manager")
}

#[instrument(level="info", skip_all, fields(oprf_key_id=tracing::field::Empty))]
async fn handle_delete(
    log: Log<LogData>,
    secret_gen: &mut DLogSecretGenService,
    secret_manager: &SecretManagerService,
) -> eyre::Result<()> {
    let key_delete = log
        .log_decode()
        .context("while decoding key deletion event")?;
    let OprfKeyRegistry::KeyDeletion { oprfKeyId } = key_delete.inner.data;
    let oprf_key_id = OprfKeyId::from(oprfKeyId);
    tracing::info!("got key deletion event for {oprf_key_id}");
    // we need to delete all the toxic waste associated with the rp id
    secret_gen.delete_oprf_key_material(oprf_key_id);
    secret_manager
        .remove_dlog_share(oprf_key_id)
        .await
        .context("while storing share to secret manager")
}
