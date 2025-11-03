//! This module provides [`ChainEventHandler`], a service that subscribes
//! to key generation events via [`KeyGenEventListenerService`].
//! It processes each event sequentially using [`DLogSecretGenService`] and [`RpMaterialStore`], then reports results back.
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
use crate::services::rp_material_store::RpMaterialStore;
use crate::services::secret_gen::DLogSecretGenService;
use crate::services::secret_manager::SecretManagerService;
use crate::services::secret_manager::StoreDLogShare;

pub enum ReportTarget {
    Chain(ChainEventResult),
    SecretManager(StoreDLogShare),
}

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
    /// * `rp_material_store` - Holds the [`crate::services::rp_material_store::RpMaterial`] for all RPs.
    /// * `cancellation_token` - Token used to signal shutdown of the handler task.
    /// * `key_gen_material` - The ZK material for computing the proofs for key generation.
    ///
    /// # Returns
    /// A [`ChainEventHandler`] that can be awaited for graceful shutdown.
    pub(crate) fn spawn(
        watcher: KeyGenEventListenerService,
        rp_material_store: RpMaterialStore,
        secret_manager: SecretManagerService,
        cancellation_token: CancellationToken,
        key_gen_material: Groth16Material,
    ) -> ChainEventHandler {
        let dlog_secret_gen_service =
            DLogSecretGenService::init(rp_material_store, key_gen_material);

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

        let report_target =
            tokio::task::block_in_place(|| handle_chain_event(&mut secret_gen, event))
                .context("while handling chain event")?;
        match report_target {
            ReportTarget::Chain(chain_event_result) => event_listener
                .report_result(chain_event_result)
                .await
                .context("while reporting chain result")?,
            ReportTarget::SecretManager(store_dlog_share) => secret_manager
                .store_dlog_share(store_dlog_share)
                .await
                .context("while storing secret")?,
        }
    }
}

/// Processes a single [`ChainEvent`] using the provided [`DLogSecretGenService`].
///
/// For round 1 and round 2 secret generation events, blocks the current thread to call synchronous methods.
/// Finalization is handled asynchronously, because we need to store the
/// resulting DLog-share into our secret-manager.
///
/// # Errors
/// Returns an error if processing the event fails.
pub(crate) fn handle_chain_event(
    secret_gen: &mut DLogSecretGenService,
    event: ChainEvent,
) -> eyre::Result<ReportTarget> {
    match event {
        ChainEvent::SecretGenRound1(SecretGenRound1Event { rp_id, threshold }) => {
            Ok(ReportTarget::Chain(ChainEventResult::SecretGenRound1(
                secret_gen.round1(rp_id, threshold),
            )))
        }

        ChainEvent::SecretGenRound2(SecretGenRound2Event { rp_id, peers }) => {
            Ok(ReportTarget::Chain(ChainEventResult::SecretGenRound2(
                secret_gen
                    .round2(rp_id, peers)
                    .context("while doing round2")?,
            )))
        }
        ChainEvent::SecretGenRound3(SecretGenRound3Event { rp_id, ciphers }) => {
            Ok(ReportTarget::Chain(ChainEventResult::SecretGenRound3(
                secret_gen
                    .round3(rp_id, ciphers)
                    .context("while doing round3")?,
            )))
        }
        ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent {
            rp_id,
            rp_public_key,
            rp_nullifier_key,
        }) => {
            let store_dlog_share = secret_gen
                .finalize(rp_id, rp_public_key, rp_nullifier_key)
                .context("while finalizing secret-gen")?;
            Ok(ReportTarget::SecretManager(store_dlog_share))
        }
    }
}
