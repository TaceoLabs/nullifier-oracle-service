#![deny(missing_docs)]
//! This crate provides the OPRF key generation functionality for TACEO:Oprf.
//!
//! It implements a service that listens for OPRF key generation events of the  `OprfKeyRegistry`
//! and participates in the distributed key generation protocol to generate and register OPRF keys.
//! The generated keys are stored securely using the provided `SecretManagerService`.
//! From there, they can be fetched by the OPRF nodes that handle OPRF requests.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use crate::{
    config::OprfKeyGenConfig,
    services::{secret_gen::DLogSecretGenService, secret_manager::SecretManagerService},
};
use alloy::{
    network::EthereumWallet,
    providers::{Provider as _, ProviderBuilder, WsConnect},
};
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_types::{chain::OprfKeyRegistry, crypto::PartyId};
use secrecy::ExposeSecret as _;

pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use services::secret_manager;

/// Starts the OPRF key generation service and waits for shutdown signal.
pub async fn start(
    config: OprfKeyGenConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-key-gen with config: {config:#?}");
    let cancellation_token = nodes_common::spawn_shutdown_task(shutdown_signal);

    tracing::info!("init oprf key-gen service..");
    tracing::info!("loading private from secret manager..");
    let private_key = secret_manager
        .load_or_insert_wallet_private_key()
        .await
        .context("while loading ETH private key from secret-manager")?;
    let address = private_key.address();
    tracing::info!("my wallet address: {address}");
    let wallet = EthereumWallet::from(private_key);

    tracing::info!("init rpc provider..");
    let ws = WsConnect::new(config.chain_ws_rpc_url.expose_secret());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?
        .erased();

    tracing::info!("loading party id..");
    let contract = OprfKeyRegistry::new(config.oprf_key_registry_contract, provider.clone());
    let party_id = PartyId(
        contract
            .getPartyIdForParticipant(address)
            .call()
            .await
            .context("while loading party id")?
            .try_into()?,
    );
    tracing::info!("we are party id: {party_id}");

    tracing::info!("init dlog secret gen service..");
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)?;
    let dlog_secret_gen_service = DLogSecretGenService::init(key_gen_material);

    tracing::info!("spawning key event watcher..");
    let key_event_watcher = tokio::spawn({
        let provider = provider.clone();
        let contract_address = config.oprf_key_registry_contract;
        let cancellation_token = cancellation_token.clone();
        services::key_event_watcher::key_event_watcher_task(
            provider,
            contract_address,
            secret_manager,
            dlog_secret_gen_service,
            cancellation_token,
        )
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, key_event_watcher).await {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }

    Ok(())
}
