//! Chain Event Handler Service
//!
//! This module provides the [`ChainEventHandler`], a service responsible for polling
//! the blockchain for relevant events, processing them, and reporting results back
//! to the chain watcher.
//!
//! The handler works in **intervals**:  
//! 1. Waits for the next interval tick.  
//! 2. Queries the chain for new events.  
//! 3. Processes each event sequentially using the [`DLogSecretGenService`] and the
//!    [`CryptoDevice`].  
//! 4. Reports the results back to the chain watcher.  
//!
//! Event processing is **single-task and sequential**, which eliminates the need for
//! locks or shared references. This simplifies mutable state management and avoids
//! threading overhead.  
//!
//! **Graceful Shutdown:**  
//! - The task will terminate when the provided [`CancellationToken`] is cancelled,  
//!   but it will finish processing any events fetched in the current interval before stopping.  
//! - If the task encounters an error during processing, it triggers the cancellation
//!   token to initiate graceful shutdown.
use std::sync::Arc;
use std::time::Duration;

use eyre::Context as _;
use oprf_types::chain::ChainEvent;
use oprf_types::chain::ChainEventResult;
use oprf_types::chain::SecretGenFinalizeContribution;
use oprf_types::chain::SecretGenFinalizeEvent;
use oprf_types::chain::SecretGenRound1Event;
use oprf_types::chain::SecretGenRound2Event;
use oprf_types::crypto::PartyId;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::services::chain_watcher::ChainWatcherService;
use crate::services::{crypto_device::CryptoDevice, secret_gen::DLogSecretGenService};

/// Handle for the chain event processing task.
///
/// Spawns a dedicated Tokio task that periodically polls the chain and processes events.
pub(crate) struct ChainEventHandler(JoinHandle<()>);

impl ChainEventHandler {
    /// Spawns a new chain event handler.
    ///
    /// # Arguments
    /// * `period` - Interval between polling the chain for new events.
    /// * `party_id` - The [`PartyId`] of this OPRF peer.
    /// * `watcher` - The [`ChainWatcherService`] used to read and report events.
    /// * `crypto_device` - The cryptographic device used to process secret shares.
    /// * `cancellation_token` - Token used to signal shutdown of the handler task.
    ///
    /// # Returns
    /// A [`ChainEventHandler`] that can be awaited for graceful shutdown.
    pub(crate) fn spawn(
        period: Duration,
        party_id: PartyId,
        watcher: ChainWatcherService,
        crypto_device: Arc<CryptoDevice>,
        cancellation_token: CancellationToken,
    ) -> ChainEventHandler {
        let dlog_secret_gen_service =
            DLogSecretGenService::init(party_id, Arc::clone(&crypto_device));
        // spawn the periodic update task
        Self(tokio::task::spawn(async move {
            match run(
                period,
                watcher,
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

/// Processes a batch of chain events.
///
/// Returns a list of results corresponding to the processed events.
///
/// # Arguments
/// * `secret_gen` - Mutable reference to the [`DLogSecretGenService`]. Must be single-owner.
/// * `events` - List of chain events to handle.
///
/// # Returns
/// Vector of [`ChainEventResult`] representing the results of processing each event.
#[instrument(level = "info", skip_all)]
pub(crate) fn handle_chain_events(
    secret_gen: &mut DLogSecretGenService,
    events: Vec<ChainEvent>,
) -> eyre::Result<Vec<ChainEventResult>> {
    // We potentially could to this in parallel, but we need mut references/locks and computing proofs has 100% CPU utilization anyways, so we stick with sequential execution for simplicity.
    let results = tokio::task::block_in_place(|| {
        let mut results = Vec::with_capacity(events.len());
        for event in events {
            match event {
                ChainEvent::SecretGenRound1(SecretGenRound1Event { rp_id, degree }) => {
                    results.push(ChainEventResult::SecretGenRound1(
                        secret_gen.round1(rp_id, degree),
                    ));
                }
                ChainEvent::SecretGenRound2(SecretGenRound2Event { rp_id, keys }) => {
                    results.push(ChainEventResult::SecretGenRound2(
                        secret_gen.round2(rp_id, keys),
                    ));
                }
                ChainEvent::SecretGenFinalize(SecretGenFinalizeEvent { rp_id, ciphers }) => {
                    secret_gen.finalize(rp_id, ciphers);
                    results.push(ChainEventResult::SecretGenFinalize(
                        SecretGenFinalizeContribution {
                            rp_id,
                            sender: secret_gen.party_id,
                        },
                    ));
                }
            }
        }
        results
    });
    Ok(results)
}

/// Periodic execution loop for polling and processing chain events.
///
/// # Arguments
/// * `period` - Interval between polls.
/// * `watcher` - Chain watcher service to retrieve and report events.
/// * `secret_gen` - Secret generation service (single-owner, not thread-safe).
/// * `cancellation_token` - Token to signal task shutdown.
async fn run(
    period: Duration,
    watcher: ChainWatcherService,
    mut secret_gen: DLogSecretGenService,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let mut interval = tokio::time::interval(period);
    // ignore the first tick as we load it anyways during startup
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {

            },
            _ = cancellation_token.cancelled() => {
                 return Ok(());
            }
        }
        tracing::trace!("check chain event fired..");
        let events = watcher
            .check_chain_events()
            .await
            .context("while checking chain events")?;
        tracing::info!("got {} chain events", events.len());
        let results =
            handle_chain_events(&mut secret_gen, events).context("while handling chain events")?;
        watcher
            .report_chain_results(results)
            .await
            .context("while reporting chain result")?;
    }
}
