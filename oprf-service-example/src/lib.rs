// #![deny(missing_docs)]
//! This crate implements a peer node for the distributed OPRF (Oblivious Pseudo-Random Function)
//! nullifier oracle service. The service participates in multi-party key generation and provides
//! partial OPRF evaluations for World ID protocol nullifiers.
//!
//! # Overview
//!
//! The OPRF peer:
//! - Participates in distributed secret generation with other peers
//! - Evaluates partial OPRF shares for authenticated clients
//! - Monitors on-chain events for key generation and merkle root updates
//! - Stores and manages cryptographic material securely via agnostic Secrets Manager (currently only AWS supported).
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use std::sync::Arc;

use alloy::network::EthereumWallet;
use eyre::Context;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_service::services::{
    event_handler::ChainEventHandler,
    key_event_watcher::{KeyGenEventListenerService, alloy_key_gen_watcher::AlloyKeyGenWatcher},
    oprf::OprfService,
    secret_manager::SecretManagerService,
};
use secrecy::ExposeSecret;

use crate::services::oprf::ExampleOprfReqAuthenticator;

pub mod config;
pub(crate) mod services;

/// Main entry point for the OPRF service.
///
/// Initializes all services, loads cryptographic material, and starts:
/// - The Axum HTTP server for API endpoints
/// - Chain event watcher for key generation
/// - Merkle root watcher for account registry
/// - Background cleanup tasks
///
/// The function blocks until the shutdown signal is triggered or an error occurs.
///
/// # Arguments
/// * `config` - Service configuration from CLI or environment
/// * `shutdown_signal` - Future that completes when shutdown is requested
///
/// # Errors
/// Returns an error if:
/// - Cryptographic material cannot be loaded
/// - Blockchain connections fail
/// - Secret manager initialization fails
/// - Server binding fails
pub async fn start(
    config: config::OprfPeerConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-service with config: {config:#?}");

    let private_key = secret_manager
        .load_or_insert_wallet_private_key()
        .await
        .context("while loading ETH private key from secret-manager")?;
    let address = private_key.address();
    tracing::info!("my wallet address: {address}");

    let wallet_address = private_key.address();
    let wallet = EthereumWallet::from(private_key);

    tracing::info!("spawning chain event listener..");
    let key_gen_watcher: KeyGenEventListenerService = Arc::new(
        AlloyKeyGenWatcher::new(
            config.chain_ws_rpc_url.expose_secret(),
            config.oprf_key_registry_contract,
            wallet,
        )
        .await
        .context("while connecting to OprfKeyRegistry contract")?,
    );

    tracing::info!("loading party id..");
    let party_id = key_gen_watcher
        .load_party_id()
        .await
        .context("while loading partyId")?;
    tracing::info!("we are party id: {party_id}");

    tracing::info!("init OPRF material-store..");
    let oprf_key_material_store = secret_manager
        .load_secrets()
        .await
        .context("while loading secrets from secret-manager")?;

    let cancellation_token = oprf_service::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf-service...");
    let oprf_service = OprfService::init(
        oprf_key_material_store.clone(),
        config.request_lifetime,
        config.session_cleanup_interval,
        party_id,
    );

    let oprf_req_auth_service = Arc::new(ExampleOprfReqAuthenticator);

    tracing::info!("spawning chain event handler..");
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)?;
    let event_handler = ChainEventHandler::spawn(
        key_gen_watcher,
        oprf_key_material_store,
        secret_manager,
        cancellation_token.clone(),
        key_gen_material,
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    let axum_rest_api =
        oprf_service::api::routes(oprf_service, oprf_req_auth_service, wallet_address);

    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, axum_rest_api)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, event_handler.wait())
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }

    Ok(())
}
