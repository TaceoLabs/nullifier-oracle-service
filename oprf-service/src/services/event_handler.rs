//! This module provides [`ChainEventHandler`], a service that subscribes
//! to key generation events via [`KeyGenEventListenerService`].
//! It processes each event sequentially using [`DLogSecretGenService`] and [`OprfKeyMaterialStore`], then reports results back.
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

use eyre::Context as _;
use groth16_material::circom::CircomGroth16Material;
use oprf_types::chain::ChainEvent;
use oprf_types::chain::ChainEventResult;
use oprf_types::chain::SecretGenFinalizeEvent;
use oprf_types::chain::SecretGenRound1Event;
use oprf_types::chain::SecretGenRound2Event;
use oprf_types::chain::SecretGenRound3Event;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::services::key_event_watcher::KeyGenEventListenerService;
use crate::services::oprf_key_material_store::OprfKeyMaterialStore;
use crate::services::secret_gen::DLogSecretGenService;
use crate::services::secret_manager::SecretManagerService;

/// Handle for the chain event processing task.
///
/// Spawns a dedicated Tokio task that subscribes at the provided
/// [`KeyGenEventListenerService`] for [`ChainEvent`]s. Calls the
/// corresponding method and reports the result back.
pub struct ChainEventHandler(JoinHandle<()>);

impl ChainEventHandler {
    /// Spawns a new chain event handler.
    ///
    /// # Arguments
    /// * `watcher` - The [`KeyGenEventListenerService`] used to read and report events from the chain.
    /// * `oprf_key_material_store` - Holds the [`crate::services::oprf_key_material_store::OprfKeyMaterial`].
    /// * `secret_manager` - An instance of [`SecretManagerService`] needed for storage/deletion of shares.
    /// * `cancellation_token` - Token used to signal shutdown of the handler task.
    /// * `key_gen_material` - The ZK material for computing the proofs for key generation.
    ///
    /// # Returns
    /// A [`ChainEventHandler`] that can be awaited for graceful shutdown.
    pub fn spawn(
        watcher: KeyGenEventListenerService,
        oprf_key_material_store: OprfKeyMaterialStore,
        secret_manager: SecretManagerService,
        cancellation_token: CancellationToken,
        key_gen_material: CircomGroth16Material,
    ) -> ChainEventHandler {
        let dlog_secret_gen_service =
            DLogSecretGenService::init(oprf_key_material_store, key_gen_material);

        Self(tokio::task::spawn(async move {
            match run(
                watcher,
                secret_manager,
                dlog_secret_gen_service,
                cancellation_token.clone(),
            )
            .await
            {
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
    pub async fn wait(self) {
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
/// * `secret_manager` — Securely persists created/updated shares.
/// * `secret_gen` — Handles secret generation.
/// * `cancellation_token` — Signals shutdown.
///
/// # Errors
/// Returns an error in one of the following cases:
/// - Subscription at `event_listener` fails
/// - The event handling fails
async fn run(
    event_listener: KeyGenEventListenerService,
    secret_manager: SecretManagerService,
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

        handle_chain_event(&mut secret_gen, &event_listener, &secret_manager, event)
            .await
            .context("while handling chain event")?;
    }
}

/// Processes a single [`ChainEvent`] using the provided [`DLogSecretGenService`].
///
/// For round 1 and round 2 secret generation events, blocks the current thread to call synchronous methods.
/// Finalization is handled asynchronously, because we need to interact with the secret manager and event-listener, which are `async`.
///
/// # Errors
/// Returns an error if either processing the event or reporting the result fails.
pub(crate) async fn handle_chain_event(
    secret_gen: &mut DLogSecretGenService,
    event_listener: &KeyGenEventListenerService,
    secret_manager: &SecretManagerService,
    event: ChainEvent,
) -> eyre::Result<()> {
    match event {
        ChainEvent::SecretGenRound1(SecretGenRound1Event {
            oprf_key_id,
            threshold,
        }) => {
            let event = tokio::task::block_in_place(|| {
                ChainEventResult::SecretGenRound1(secret_gen.round1(oprf_key_id, threshold))
            });
            event_listener
                .report_result(event)
                .await
                .context("while reporting chain result")
        }
        ChainEvent::SecretGenRound2(SecretGenRound2Event { oprf_key_id, peers }) => {
            let event = tokio::task::block_in_place(|| {
                eyre::Ok(ChainEventResult::SecretGenRound2(
                    secret_gen
                        .round2(oprf_key_id, peers)
                        .context("while doing round2")?,
                ))
            })?;
            event_listener
                .report_result(event)
                .await
                .context("while reporting chain result")
        }
        ChainEvent::SecretGenRound3(SecretGenRound3Event {
            oprf_key_id,
            ciphers,
        }) => {
            let event = ChainEventResult::SecretGenRound3(
                secret_gen
                    .round3(oprf_key_id, ciphers)
                    .context("while doing round3")?,
            );
            event_listener
                .report_result(event)
                .await
                .context("while reporting chain result")
        }
        ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
            oprf_key_id,
            oprf_public_key,
        }) => {
            let store_dlog_share = secret_gen
                .finalize(oprf_key_id, oprf_public_key)
                .context("while finalizing secret-gen")?;
            secret_manager
                .store_dlog_share(store_dlog_share)
                .await
                .context("while storing share to secret manager")
        }
        ChainEvent::DeleteOprfKeyMaterial(oprf_key_id) => {
            // we need to delete all the toxic waste associated with the rp id
            secret_gen.delete_oprf_key_material(oprf_key_id);
            secret_manager
                .remove_dlog_share(oprf_key_id)
                .await
                .context("while storing share to secret manager")
        }
    }
}
