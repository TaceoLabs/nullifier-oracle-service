#![deny(missing_docs)]
//! This crate provides the core functionality of a node node for TACEO:Oprf.
//!
//! When implementing a concrete instantiation of TACEO:Oprf, projects use this composable library to build their flavor of the distributed OPRF protocol. The main entry point for implementations is the [`init`] method. It returns an `axum::Router` that should be incorporated into a larger `axum` server that provides project-based functionality for authentication.
//!
//! Additionally, implementations must provide their project-specific authentication. For that, this library exposes the [`OprfRequestAuthenticator`] trait. A call to `init` expects an [`OprfRequestAuthService`], which is a dyn object of `OprfRequestAuthenticator`.
//!
//! The general workflow is as follows:
//! 1) End-users initiate a session at $n$ nodes.
//!    - the router created by `init` receives the request
//!    - the router calls [`OprfRequestAuthenticator::verify`] of the provided authentication implementation. This can be anything from no verification to providing credentials.
//!    - the node creates a session identified by a UUID and sends a commitment back to the user.
//! 2) As soon as end-users have opened $t$ sessions, they compute challenges for the answering nodes.
//!    - the router answers the challenge and deletes all information containing the sessions.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
//!
//! Clients will connect via web-sockets to the OPRF node. Axum supports both HTTP/1.1 and HTTP/2.0 web-socket connections, therefore we accept connections with `any`.
///
/// If you want to enable HTTP/2.0, you either have to do it by hand or by calling `axum::serve`, which enabled HTTP/2.0 by default. Have a look at [Axum's HTTP2.0 example](https://github.com/tokio-rs/axum/blob/aeff16e91af6fa76efffdee8f3e5f464b458785b/examples/websockets-http2/src/main.rs#L57).
use crate::{
    config::OprfNodeConfig,
    services::{secret_gen::DLogSecretGenService, secret_manager::SecretManagerService},
};
use alloy::{
    network::EthereumWallet,
    providers::{Provider as _, ProviderBuilder, WsConnect},
};
use async_trait::async_trait;
use core::fmt;
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_types::api::v1::OprfRequest;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use std::sync::Arc;
use tokio::signal;
use tokio_util::sync::CancellationToken;

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub mod oprf_key_registry;
pub(crate) mod services;

pub use services::oprf_key_material_store;
pub use services::secret_manager;

/// Trait defining the authentication mechanism for OPRF requests.
///
/// This trait enables the verification of OPRF requests to ensure they are
/// properly authenticated before processing. It is designed to be implemented
/// by authentication services that can validate the authenticity of incoming
/// OPRF requests.
#[async_trait]
pub trait OprfRequestAuthenticator: Send + Sync {
    /// Represents the authentication data type included in the OPRF request.
    type RequestAuth;
    /// The error type that may be returned by the [`OprfRequestAuthenticator`] on [`OprfRequestAuthenticator::verify`].
    ///
    /// This method shall implement `fmt::Display` because a human-readable message will be sent back to the user for troubleshooting.
    ///
    /// **Note:** it is very important that `fmt::Display` does not print any sensitive information. For debugging information, use `fmt::Debug`.
    type RequestAuthError: Send + 'static + std::error::Error;

    /// Verifies the authenticity of an OPRF request.
    async fn verify(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError>;
}

/// An implementation of `OprfRequestAuthenticator` that performs no authentication.
pub struct WithoutAuthentication;

/// Error type for [`WithoutAuthentication`]. Will never be constructed during ordinary flow.
#[derive(Debug, Clone, Copy)]
pub struct WithoutAuthenticationError;

impl fmt::Display for WithoutAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("you failed the no-authentication authentication")
    }
}

impl std::error::Error for WithoutAuthenticationError {}

#[async_trait]
impl OprfRequestAuthenticator for WithoutAuthentication {
    type RequestAuth = ();
    type RequestAuthError = WithoutAuthenticationError;

    async fn verify(
        &self,
        _req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        Ok(())
    }
}

/// Dynamic trait object for `OprfRequestAuthenticator` service.
pub type OprfRequestAuthService<RequestAuth, RequestAuthError> = Arc<
    dyn OprfRequestAuthenticator<RequestAuth = RequestAuth, RequestAuthError = RequestAuthError>,
>;

/// Initializes the OPRF service.
///
/// This function sets up the necessary components and services required for the OPRF node
/// to operate. It performs the following steps:
///
/// 1. Loads or generates the Ethereum wallet private key from the secret manager.
/// 2. Initializes the Ethereum RPC provider using the wallet and the provided WebSocket RPC URL.
/// 3. Loads the party ID from the OPRF key registry contract.
/// 4. Loads cryptographic secrets from the secret manager.
/// 5. Initializes the distributed logarithm (DLog) secret generation service using the key generation material.
/// 6. Spawns a task to watch for key events from the OPRF key registry contract and updates the secret manager accordingly.
/// 7. Initializes the OPRF service, which handles OPRF requests and session management.
/// 8. Sets up the Axum-based REST API routes for the OPRF service.
///
/// # Returns
///
/// Returns a tuple containing:
/// - An Axum `Router` instance with the configured REST API routes.
/// - A `JoinHandle` for the key event watcher task.
pub async fn init<
    RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
    RequestAuthError: Send + 'static + std::error::Error,
>(
    config: OprfNodeConfig,
    secret_manager: SecretManagerService,
    oprf_req_auth_service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, tokio::task::JoinHandle<eyre::Result<()>>)> {
    tracing::info!("loading private from secret manager..");
    let private_key = secret_manager
        .load_or_insert_wallet_private_key()
        .await
        .context("while loading ETH private key from secret-manager")?;
    let address = private_key.address();
    tracing::info!("my wallet address: {address}");
    let wallet_address = private_key.address();
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
    let party_id =
        oprf_key_registry::load_party_id(config.oprf_key_registry_contract, provider.clone())
            .await
            .context("while loading partyId")?;
    tracing::info!("we are party id: {party_id}");

    tracing::info!("init OPRF material-store..");
    let oprf_key_material_store = secret_manager
        .load_secrets()
        .await
        .context("while loading secrets from secret-manager")?;

    tracing::info!("init dlog secret gen service..");
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .build_from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)?;
    let dlog_secret_gen_service =
        DLogSecretGenService::init(oprf_key_material_store.clone(), key_gen_material);

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

    tracing::info!("init oprf-service...");
    let axum_rest_api = api::routes(
        party_id,
        oprf_key_material_store,
        oprf_req_auth_service,
        wallet_address,
        config.ws_max_message_size,
        config.session_lifetime,
    );

    Ok((axum_rest_api, key_event_watcher))
}

/// Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary.
pub fn version_info() -> String {
    format!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version::git_version!(fallback = "UNKNOWN"))
    )
}

/// Spawns a shutdown task and creates an associated [`CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html). This task will complete when either the provided `shutdown_signal` futures completes or if some other tasks cancels the shutdown token. The associated shutdown token will be cancelled either way.
///
/// Waiting for the shutdown token is the preferred way to wait for termination.
pub fn spawn_shutdown_task(
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

/// The default shutdown signal for the oprf-service. Triggered when pressing CTRL+C on most systems.
pub async fn default_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
