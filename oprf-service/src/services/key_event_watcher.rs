//! Alloy-based Key Generation Event Watcher
//!
//! This module provides [`key_event_watcher_task`], an task than can be spawned to
//! monitor an on-chain OprfKeyRegistry contract for key generation events.
//!
//! The watcher subscribes to various key generation events (Round 1, 2, 3, and Finalize)
//! and reports contributions back to the contract. It uses Alloy for blockchain interaction.

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U160},
    providers::{DynProvider, Provider as _},
    rpc::types::Filter,
    sol_types::SolEvent as _,
};
use eyre::Context;
use futures::StreamExt as _;
use oprf_types::{
    OprfKeyId,
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, PeerPublicKeyList, SecretGenCiphertext},
};
use tokio_util::sync::CancellationToken;

use crate::{
    oprf_key_registry::OprfKeyRegistry,
    services::{secret_gen::DLogSecretGenService, secret_manager::SecretManagerService},
};

/// Background task that subscribes to key generation events and handles them.
///
/// Connects to the blockchain via WebSocket and verifies that the
/// OprfKeyRegistry contract is ready.
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
        provider.erased(),
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
                let round1 = log
                    .log_decode()
                    .context("while decoding secret-gen round1 event")?;
                let OprfKeyRegistry::SecretGenRound1 {
                    oprfKeyId,
                    threshold,
                } = round1.inner.data;
                let oprf_key_id = OprfKeyId::from(oprfKeyId);
                let threshold = u16::try_from(threshold)?;
                let res = secret_gen.round1(oprf_key_id, threshold);
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
            }
            Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
                tracing::debug!("got round 2 event!");
                let round2 = log
                    .log_decode()
                    .context("while decoding secret-gen round2 event")?;
                let OprfKeyRegistry::SecretGenRound2 { oprfKeyId } = round2.inner.data;
                let (oprf_key_id, peers) =
                    prepare_round2_event(oprfKeyId, contract_address, provider.clone())
                        .await
                        .context("while preparing round2 event")?;
                // block_in_place here because we do a lot CPU work
                let res = tokio::task::block_in_place(|| {
                    secret_gen
                        .round2(oprf_key_id, peers)
                        .context("while doing round2")
                })?;
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
            }
            Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
                tracing::debug!("got round 3 event!");
                let round3 = log
                    .log_decode()
                    .context("while decoding secret-gen round3 event")?;
                let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = round3.inner.data;
                let (oprf_key_id, ciphers) =
                    prepare_round3_event(oprfKeyId, contract_address, provider.clone())
                        .await
                        .context("while preparing round3 event")?;
                let res = secret_gen
                    .round3(oprf_key_id, ciphers)
                    .context("while doing round2")?;
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
            }
            Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
                let finalize = log
                    .log_decode()
                    .context("while decoding secret-gen finalize event")?;
                let OprfKeyRegistry::SecretGenFinalize { oprfKeyId } = finalize.inner.data;
                let (oprf_key_id, oprf_public_key) =
                    prepare_finalize_event(oprfKeyId, contract_address, provider.clone())
                        .await
                        .context("while preparing finalize event")?;
                let store_dlog_share = secret_gen
                    .finalize(oprf_key_id, oprf_public_key)
                    .context("while finalizing secret-gen")?;
                secret_manager
                    .store_dlog_share(store_dlog_share)
                    .await
                    .context("while storing share to secret manager")?;
            }

            Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
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
                    .context("while storing share to secret manager")?;
            }
            x => {
                tracing::info!("unknown event: {x:?}");
            }
        }
    }
    Ok(())
}

/// Prepares a Round 2 event by fetching ephemeral public keys from the contract.
///
/// Queries the OprfKeyRegistry contract to retrieve the ephemeral public keys
/// submitted by all peers in Round 1.
async fn prepare_round2_event(
    oprf_key_id: U160,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<(OprfKeyId, PeerPublicKeyList)> {
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    let peers = contract
        .checkIsParticipantAndReturnEphemeralPublicKeys(oprf_key_id)
        .call()
        .await
        .context("while loading eph keys")?;
    // TODO handle error case better - we want to know which one send wrong key
    let list = peers
        .into_iter()
        .map(EphemeralEncryptionPublicKey::try_from)
        .collect::<eyre::Result<Vec<_>>>()?;
    Ok((OprfKeyId::from(oprf_key_id), PeerPublicKeyList::from(list)))
}

/// Prepares a Round 3 event by fetching ciphertexts from the contract.
///
/// Queries the OprfKeyRegistry contract to retrieve the ciphertexts
/// submitted by all peers in Round 2.
async fn prepare_round3_event(
    oprf_key_id: U160,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<(OprfKeyId, Vec<SecretGenCiphertext>)> {
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    let ciphers = contract
        .checkIsParticipantAndReturnRound2Ciphers(oprf_key_id)
        .call()
        .await
        .context("while loading ciphers")?;
    Ok((
        OprfKeyId::from(oprf_key_id),
        ciphers
            .into_iter()
            .map(SecretGenCiphertext::try_from)
            .collect::<eyre::Result<Vec<_>>>()?,
    ))
}

/// Prepares a finalize event by fetching the OPRF public-key from the contract.
async fn prepare_finalize_event(
    oprf_key_id: U160,
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<(OprfKeyId, OprfPublicKey)> {
    let contract = OprfKeyRegistry::new(contract_address, provider.clone());
    let oprf_public_key = contract.getOprfPublicKey(oprf_key_id).call().await?;
    Ok((
        OprfKeyId::from(oprf_key_id),
        OprfPublicKey::new(oprf_public_key.try_into()?),
    ))
}
