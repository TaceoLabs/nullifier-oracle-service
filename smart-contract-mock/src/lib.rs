use std::sync::Arc;

use axum::{Router, extract::FromRef};
use eyre::Context as _;
use oprf_types::sc_mock::MerkleRootUpdate;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;

use crate::{
    config::SmartContractMockConfig,
    services::{
        merkle_registry::MerkleRootRegistry, peer_key_registry::OprfPeerKeyRegistry,
        rp_key_gen::RpNullifierGenService, rp_registry::RpRegistry,
    },
};

mod api;
pub mod config;
mod merkle;
mod services;

#[derive(Clone)]
pub(crate) struct AppState {
    merkle_registry: MerkleRootRegistry,
    rp_registry: RpRegistry,
    key_gen_service: RpNullifierGenService,
    peer_keys: OprfPeerKeyRegistry,
}

impl FromRef<AppState> for MerkleRootRegistry {
    fn from_ref(input: &AppState) -> Self {
        input.merkle_registry.clone()
    }
}

impl FromRef<AppState> for RpRegistry {
    fn from_ref(input: &AppState) -> Self {
        input.rp_registry.clone()
    }
}

impl FromRef<AppState> for broadcast::Receiver<MerkleRootUpdate> {
    fn from_ref(input: &AppState) -> Self {
        input.merkle_registry.subscribe_updates()
    }
}

impl FromRef<AppState> for RpNullifierGenService {
    fn from_ref(input: &AppState) -> Self {
        input.key_gen_service.clone()
    }
}

impl FromRef<AppState> for OprfPeerKeyRegistry {
    fn from_ref(input: &AppState) -> Self {
        input.peer_keys.clone()
    }
}

pub async fn start(
    config: SmartContractMockConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting smart contract mock with config: {config:#?}");
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::warn!("cannot install rustls crypto provider!");
        tracing::warn!("we continue but this should not happen...");
    };
    let config = Arc::new(config);

    // load the public keys from the OPRF services
    let peer_keys = OprfPeerKeyRegistry::load_from_aws(&config)
        .await
        .context("while loading public keys from AWS")?;

    tracing::info!(
        "creating merkle tree with {} random nodes (this may take some time)",
        config.init_registry_size
    );
    let pk_registry = MerkleRootRegistry::with_random_elements(
        Arc::clone(&config),
        &mut ChaCha12Rng::seed_from_u64(config.seed),
    );

    tracing::info!(
        "starting add pk task with interval: {}",
        humantime::format_duration(config.add_pk_interval)
    );
    pk_registry.start_add_pk_task(config.add_pk_interval);

    tracing::info!("spawning rp registry..");
    let rp_registry = RpRegistry::init();

    tracing::info!("spawning key gen service..");
    let key_gen_service = RpNullifierGenService::init(Arc::clone(&config), rp_registry.clone());

    tracing::info!(
        "starting add RP task with interval: {}",
        humantime::format_duration(config.add_rp_interval)
    );
    key_gen_service.start_add_rp_task(config.add_rp_interval);

    let app_state = AppState {
        merkle_registry: pk_registry,
        rp_registry,
        key_gen_service,
        peer_keys,
    };

    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .context("while binding tcp listener")?;
    let router = Router::new()
        .nest("/api/", api::build())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);
    tracing::info!(
        "starting axum server on {}",
        listener
            .local_addr()
            .map(|x| x.to_string())
            .unwrap_or(String::from("invalid addr"))
    );
    let axum_result = axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
        .await;
    tracing::info!("axum server shutdown");
    if let Err(err) = axum_result {
        tracing::error!("got error from axum: {err:?}");
    }

    Ok(())
}

fn spawn_shutdown_task(
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> CancellationToken {
    let cancellation_token = CancellationToken::new();
    let task_token = cancellation_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_signal => {
                tracing::info!("Received EXTERNAL shutdown");
                task_token.cancel();
            }
            _ = task_token.cancelled() => {
                tracing::info!("Received INTERNAL shutdown");
            }
        }
    });
    cancellation_token
}
