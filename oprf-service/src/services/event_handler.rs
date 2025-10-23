//! This module provides [`ChainEventHandler`], a service that subscribes
//! to key generation events via [`KeyGenEventListenerService`].
//! It processes each event sequentially using [`DLogSecretGenService`] and [`CryptoDevice`], then reports results back.
//!
//! **Event Flow:**
//! 1. Subscribes to event stream.
//! 2. Handles each event one by one (no concurrency).
//! 3. Reports results after processing.
//!
//! Event processing is **single-task and sequential**, which eliminates the need for
//! locks or shared references. This simplifies mutable state management and avoids
//! threading overhead.  
//!
//! **Shutdown:**
//! - The task exits when the [`CancellationToken`] is triggered.
//! - Any events already received are processed before shutdown.
//! - On error, triggers cancellation for graceful exit.

use std::sync::Arc;

use eyre::Context as _;
use oprf_types::chain::ChainEvent;
use oprf_types::chain::ChainEventResult;
use oprf_types::chain::SecretGenFinalizeEvent;
use oprf_types::chain::SecretGenRound1Event;
use oprf_types::chain::SecretGenRound2Event;
use oprf_types::chain::SecretGenRound3Event;
use oprf_zk::Groth16Material;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::services::key_event_watcher::KeyGenEventListenerService;
use crate::services::{crypto_device::CryptoDevice, secret_gen::DLogSecretGenService};

/// Handle for the chain event processing task.
///
/// Spawns a dedicated Tokio task that subscribes at the provided
/// [`KeyGenEventListenerService`] for [`ChainEvent`]s. Calls the
/// corresponding method and reports the result back.
pub(crate) struct ChainEventHandler(JoinHandle<()>);

impl ChainEventHandler {
    /// Spawns a new chain event handler.
    ///
    /// # Arguments
    /// * `watcher` - The [`KeyGenEventListenerService`] used to read and report events from the chain.
    /// * `crypto_device` - The cryptographic device used to process secret shares.
    /// * `cancellation_token` - Token used to signal shutdown of the handler task.
    ///
    /// # Returns
    /// A [`ChainEventHandler`] that can be awaited for graceful shutdown.
    pub(crate) fn spawn(
        watcher: KeyGenEventListenerService,
        crypto_device: Arc<CryptoDevice>,
        cancellation_token: CancellationToken,
        key_gen_material: Groth16Material,
    ) -> ChainEventHandler {
        let dlog_secret_gen_service =
            DLogSecretGenService::init(Arc::clone(&crypto_device), key_gen_material);

        Self(tokio::task::spawn(async move {
            match run(watcher, dlog_secret_gen_service, cancellation_token.clone()).await {
                Ok(_) => tracing::info!("shutdown of ChainEventHandler"),
                Err(err) => tracing::error!("ChainEventHandler encountered an error: {err:?}"),
            }
            cancellation_token.cancel();
        }))
    }

    /// Waits for the handler task to finish.
    ///
    /// This will return once the cancellation token is triggered and the periodic
    /// loop has completed.
    pub(crate) async fn wait(self) {
        self.0.await.expect("did not panic");
    }
}

/// Main loop for polling and processing chain events.
///
/// Subscribes to key generation events from `event_listener`, processes each event with
/// `secret_gen`, and reports the result. The loop exits when `cancellation_token` is triggered.
///
/// # Arguments
/// * `event_listener` — Receives and reports chain events.
/// * `secret_gen` — Handles secret generation.
/// * `cancellation_token` — Signals shutdown.
///
/// # Errors
/// Returns an error in one of the following cases:
/// - Subscription at `event_listener` fails
/// - The event handling fails
async fn run(
    event_listener: KeyGenEventListenerService,
    mut secret_gen: DLogSecretGenService,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let mut channel = event_listener
        .subscribe()
        .await
        .context("while subscribing to key gen events")?;

    loop {
        let event = tokio::select! {
            event = channel.recv() => {
                event.ok_or_else(||eyre::eyre!("subscribe channel was dropped in event handler"))?
            }
            _ = cancellation_token.cancelled() => {
                return Ok(());
            }
        };

        let result = tokio::task::block_in_place(|| handle_chain_event(&mut secret_gen, event))
            .context("while handling chain event")?;
        event_listener
            .report_result(result)
            .await
            .context("while reporting chain result")?;
    }
}

/// Processes a single [`ChainEvent`] using the provided [`DLogSecretGenService`].
///
/// # Errors
/// Returns an error if processing the event fails.
///
/// # Notes
/// This function performs heavy CPU work and should not be run on a async runtime.
pub(crate) fn handle_chain_event(
    secret_gen: &mut DLogSecretGenService,
    event: ChainEvent,
) -> eyre::Result<ChainEventResult> {
    match event {
        ChainEvent::SecretGenRound1(SecretGenRound1Event { rp_id, threshold }) => Ok(
            ChainEventResult::SecretGenRound1(secret_gen.round1(rp_id, threshold)),
        ),
        ChainEvent::SecretGenRound2(SecretGenRound2Event { rp_id }) => {
            Ok(ChainEventResult::SecretGenRound2(
                secret_gen.round2(rp_id).context("while doing round2")?,
            ))
        }
        ChainEvent::SecretGenRound3(SecretGenRound3Event { rp_id, ciphers }) => {
            Ok(ChainEventResult::SecretGenRound3(
                secret_gen
                    .round3(rp_id, ciphers)
                    .context("while doing round3")?,
            ))
        }
        ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
            rp_id,
            rp_public_key,
            rp_nullifier_key,
        }) => {
            secret_gen
                .finalize(rp_id, rp_public_key, rp_nullifier_key)
                .context("while finalizing secret-gen")?;
            Ok(ChainEventResult::NothingToReport)
        }
    }
}
