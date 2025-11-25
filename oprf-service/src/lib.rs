#![deny(missing_docs)]
//! This crate provides the core functionality of a peer node for TACEO:Oprf.
//!
//! When implementing a concrete instantiation of TACEO:Oprf, projects use this composable library to build their flavor of the distributed OPRF protocol. The main entry point for implementations is the [`init`] method. It returns an `axum::Router` that should be incorporated into a larger `axum` server that provides project based functionality for authentication.
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).

use alloy::{
    network::EthereumWallet,
    providers::{Provider as _, ProviderBuilder, WsConnect},
};
use axum::response::IntoResponse;
use eyre::Context as _;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use secrecy::ExposeSecret as _;
use serde::{Serialize, de::DeserializeOwned};
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::{
    config::OprfPeerConfig,
    services::{
        oprf::OprfService, secret_gen::DLogSecretGenService, secret_manager::SecretManagerService,
    },
};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub mod oprf_key_registry;
pub(crate) mod services;

pub use services::oprf::{OprfReqAuthService, OprfReqAuthenticator};
pub use services::oprf_key_material_store;
pub use services::secret_manager;

/// Initializes the OPRF service.
///
/// This function sets up the necessary components and services required for the OPRF peer
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
    ReqAuth: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    ReqAuthError: IntoResponse + Send + Sync + 'static,
>(
    config: OprfPeerConfig,
    secret_manager: SecretManagerService,
    oprf_req_auth_service: OprfReqAuthService<ReqAuth, ReqAuthError>,
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
    let oprf_service = OprfService::init(
        oprf_key_material_store.clone(),
        config.request_lifetime,
        config.session_cleanup_interval,
        party_id,
    );

    let axum_rest_api = api::routes(oprf_service, oprf_req_auth_service, wallet_address);

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

/// Spawns a shutdown task and creates an associated [CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html). This task will complete when either the provided shutdown_signal futures completes or if some other tasks cancels the shutdown token. The associated shutdown token will be cancelled either way.
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::{collections::HashMap, time::Duration};

    use ark_ff::UniformRand;
    use async_trait::async_trait;
    use axum::Router;
    use axum_test::TestServer;
    use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogShareShamir};
    use oprf_types::api::v1::{ChallengeRequest, OprfRequest, ShareIdentifier};
    use oprf_types::crypto::{OprfPublicKey, PartyId};
    use oprf_types::{OprfKeyId, ShareEpoch};
    use rand::Rng as _;
    use uuid::Uuid;

    use crate::services::oprf::{OprfReqAuthenticator, OprfService};
    use crate::services::oprf_key_material_store::{OprfKeyMaterial, OprfKeyMaterialStore};

    use super::*;

    struct TestOprfReqAuthenticator;

    #[async_trait]
    impl OprfReqAuthenticator for TestOprfReqAuthenticator {
        type ReqAuth = ();
        type ReqAuthError = ();

        async fn verify(
            &self,
            _req: &OprfRequest<Self::ReqAuth>,
        ) -> Result<(), Self::ReqAuthError> {
            Ok(())
        }
    }

    struct TestSetup {
        server: TestServer,
        oprf_service: OprfService,
        oprf_req: OprfRequest<()>,
        challenge_req: ChallengeRequest,
    }

    impl TestSetup {
        async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();

            let share_epoch = ShareEpoch::default();

            let oprf_key_id = OprfKeyId::new(rng.r#gen());

            let request_id = Uuid::new_v4();
            let action = ark_babyjubjub::Fq::rand(&mut rng);
            let mt_index = rng.gen_range(0..(1 << 30)) as u64;
            let query_hash = oprf_core::oprf::client::generate_query(
                mt_index.into(),
                oprf_key_id.into(),
                action,
            );
            let (blinded_request, _blinding_factor) =
                oprf_core::oprf::client::blind_query(query_hash, &mut rng);
            let oprf_req = OprfRequest {
                request_id,
                blinded_query: blinded_request.blinded_query(),
                share_identifier: ShareIdentifier {
                    oprf_key_id,
                    share_epoch,
                },
                auth: (),
            };
            let challenge_req = ChallengeRequest {
                request_id,
                challenge: DLogCommitmentsShamir::new(
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    vec![1, 2, 3],
                ),
                share_identifier: ShareIdentifier {
                    oprf_key_id,
                    share_epoch,
                },
            };

            let oprf_key_material = OprfKeyMaterialStore::new(HashMap::from([(
                oprf_key_id,
                OprfKeyMaterial::new(
                    HashMap::from([(
                        ShareEpoch::default(),
                        DLogShareShamir::from(ark_babyjubjub::Fr::rand(&mut rng)),
                    )]),
                    OprfPublicKey::new(rng.r#gen()),
                ),
            )]));

            let request_lifetime = Duration::from_secs(5 * 60);
            let session_cleanup_interval = Duration::from_secs(30);
            let oprf_service = OprfService::init(
                oprf_key_material,
                request_lifetime,
                session_cleanup_interval,
                PartyId(0),
            );
            let routes = Router::new().nest(
                "/api/v1",
                api::v1::routes(oprf_service.clone(), Arc::new(TestOprfReqAuthenticator)),
            );
            let server = TestServer::builder()
                .expect_success_by_default()
                .mock_transport()
                .build(routes)
                .unwrap();

            Ok(Self {
                server,
                oprf_service,
                oprf_req,
                challenge_req,
            })
        }
    }

    #[tokio::test]
    async fn test_init() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_blinded_query_identity_is_bad_request() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.blinded_query = ark_babyjubjub::EdwardsAffine::zero();
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("blinded query not allowed to be identity");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_unknown_oprf_key_id() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let unknown_oprf_key_id = OprfKeyId::new(rand::random());
        let mut req = setup.oprf_req;
        req.share_identifier.oprf_key_id = unknown_oprf_key_id;

        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!("cannot find RP with id: {unknown_oprf_key_id}"));
        res.assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_unknown_share_epoch() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let unknown_share_epoch = ShareEpoch::new(rand::random());
        let mut req = setup.oprf_req;
        req.share_identifier.share_epoch = unknown_share_epoch;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!(
            "cannot find share with epoch {unknown_share_epoch}",
        ));
        res.assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        let req = setup.challenge_req;
        setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            !setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_finish_without_init() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.challenge_req;
        setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .expect_failure()
            .await
            .assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish_unknown_share_epoch() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        let unknown_share_epoch = ShareEpoch::new(rand::random());
        let mut req = setup.challenge_req;
        req.share_identifier.share_epoch = unknown_share_epoch;
        let res = setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!(
            "cannot find share with epoch {unknown_share_epoch}",
        ));
        res.assert_status_not_found();
        Ok(())
    }
}
