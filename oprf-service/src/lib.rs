#![deny(missing_docs)]
//! OPRF Peer Service
//!
//! This crate implements the main entry point, configuration, metrics, telemetry,
//! and service components for an OPRF peer.
//!
//! TODO TOP LEVEL DOCUMENTATION
//!
//! # Key Components
//! - `AppState`: Holds shared state for Axum, including OPRF service and chain watcher.
//! - `start()`: Main async entry point to start the service, initialize crypto, secret manager, and spawn Axum server and background tasks.
//! - `spawn_shutdown_task()`: Helper to create a `CancellationToken` for coordinated shutdown.
//! - `default_shutdown_signal()`: Default shutdown signal using CTRL+C or UNIX terminate signals.
//!
//! # Modules
//! - `config`: Configuration via environment variables or CLI.
//! - `metrics`: Metrics keys and helpers.
//! - `telemetry`: Logging and tracing initialization.
//! - `services`: Core services like OPRF evaluation, chain watcher, and secret management.
//! - `api`: REST API routes.
use std::{fs::File, sync::Arc};

use ark_serde_compat::groth16::Groth16VerificationKey;
use axum::extract::FromRef;
use eyre::Context;
use oprf_types::crypto::PartyId;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::{
    config::OprfPeerConfig,
    services::{
        chain_watcher::{ChainWatcherService, http_mock::HttpMockWatcher},
        crypto_device::CryptoDevice,
        event_handler::ChainEventHandler,
        oprf::OprfService,
        secret_manager::aws::AwsSecretManager,
    },
};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;
pub mod telemetry;

/// Main application state for the OPRF-Peer used for Axum.
///
/// If Axum should be able to extract services, it should be added to
/// the `AppState`.
#[derive(Clone)]
pub(crate) struct AppState {
    config: Arc<OprfPeerConfig>,
    oprf_service: OprfService,
    party_id: PartyId,
}

impl FromRef<AppState> for Arc<OprfPeerConfig> {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.config)
    }
}

impl FromRef<AppState> for OprfService {
    fn from_ref(input: &AppState) -> Self {
        input.oprf_service.clone()
    }
}

impl FromRef<AppState> for PartyId {
    fn from_ref(input: &AppState) -> Self {
        input.party_id
    }
}

/// Main entry point for the OPRF-Service.
/// TODO better docs
pub async fn start(
    config: config::OprfPeerConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    // install rustls crypto provider
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::warn!("cannot install rustls crypto provider!");
        tracing::warn!("we continue but this should not happen...");
    };
    let config = Arc::new(config);

    tracing::info!(
        "loading Groth16 verification key from: {:?}",
        config.user_verification_key_path
    );
    let vk = File::open(&config.user_verification_key_path)
        .context("while opening file to verification key")?;
    let vk: Groth16VerificationKey = serde_json::from_reader(vk)
        .context("while parsing Groth16 verification key for user proof")?;

    // Load the secret manager. For now we only support AWS.
    // For local development, we also allow to load secret from file. Still the local secret-manager will assert that we run in Dev environment
    let secret_manager = Arc::new(AwsSecretManager::init(Arc::clone(&config)).await);

    // TODO load all RP_ids from SC

    tracing::info!("init crypto device..");
    let crypto_device = Arc::new(
        CryptoDevice::init(secret_manager, vec![])
            .await
            .context("while initiating crypto-device")?,
    );

    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    tracing::info!("spawn chain watcher..");
    // spawn the chain watcher
    let chain_watcher: ChainWatcherService = Arc::new(
        HttpMockWatcher::init(
            Arc::clone(&config),
            Arc::clone(&crypto_device),
            cancellation_token.clone(),
        )
        .await
        .context("while starting chain watcher")?,
    );

    tracing::info!("loading party id..");
    // load our party id
    let party_id = chain_watcher
        .get_party_id()
        .await
        .context("while loading partyID")?;
    tracing::info!("we are party id: {party_id}");

    // start oprf-service service
    tracing::info!("init oprf-service...");
    let oprf_service = OprfService::init(
        Arc::clone(&config),
        Arc::clone(&crypto_device),
        Arc::clone(&chain_watcher),
        vk.into(),
    );

    tracing::info!("spawning chain event handler..");
    // spawn the periodic task
    let event_handler = ChainEventHandler::spawn(
        config.chain_check_interval,
        party_id,
        Arc::clone(&chain_watcher),
        Arc::clone(&crypto_device),
        cancellation_token.clone(),
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    let axum_rest_api = api::new_app(Arc::clone(&config), party_id, oprf_service);

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
        "waiting for shutdown of services (max wait time {} as secs)..",
        humantime::format_duration(config.max_wait_time_shutdown)
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

/// Spawns a shutdown task and creates an associated [CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html). This task will complete when either the provided shutdown_signal futures completes or if some other tasks cancels the shutdown token. The associated shutdown token will be cancelled either way.
///
/// Waiting for the shutdown token is the preferred way to wait for termination.
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
    use std::str::FromStr;
    use std::{collections::HashMap, fs::File, path::PathBuf, time::Duration};

    use ark_ff::UniformRand;
    use ark_serde_compat::groth16::Groth16VerificationKey;
    use axum_test::TestServer;
    use oprf_types::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch, sc_mock::MerkleRootUpdate};

    use crate::services::crypto_device::dlog_storage::RpMaterial;
    use crate::{
        config::Environment,
        services::{
            chain_watcher::test::TestWatcher,
            crypto_device::{CryptoDevice, DLogShare, PeerPrivateKey},
            secret_manager::test::TestSecretManager,
        },
    };

    use super::*;

    async fn test_server() -> eyre::Result<TestServer> {
        let mut rng = rand::thread_rng();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config = OprfPeerConfig {
            environment: Environment::Dev,
            bind_addr: "0.0.0.0:10000".to_string().parse().unwrap(),
            input_max_body_limit: 32768,
            request_lifetime: Duration::from_secs(5 * 60),
            session_cleanup_interval: Duration::from_micros(10),
            max_concurrent_jobs: 100000,
            max_wait_time_shutdown: Duration::from_secs(10),
            session_store_mailbox: 4096,
            user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
            chain_url: "foo".to_string(),
            chain_check_interval: Duration::from_secs(60),
            chain_epoch_max_difference: 10,
            private_key_secret_id: "oprf/sk".to_string(),
            dlog_share_secret_id_suffix: "oprf/shares/".to_string(),
            max_merkle_store_size: 10,
        };
        let config = Arc::new(config);
        let secret_manager = Arc::new(TestSecretManager::new(
            PeerPrivateKey::from(ark_babyjubjub::Fr::rand(&mut rng)),
            HashMap::from([(
                RpId::new(0),
                RpMaterial::new(
                    HashMap::from([(
                        ShareEpoch::default(),
                        DLogShare::from(ark_babyjubjub::Fr::rand(&mut rng)),
                    )]),
                    k256::SecretKey::new(k256::Scalar::ONE.into())
                        .public_key()
                        .into(),
                ),
            )]),
        ));
        let crypto_device = Arc::new(CryptoDevice::init(secret_manager, Vec::new()).await?);
        let chain_watcher = Arc::new(TestWatcher::new(
            vec![MerkleRootUpdate {
                hash: MerkleRoot::new(ark_babyjubjub::Fq::from_str(
                    "12184867385685695781627163047456512405047415901037550089919079425163309680784",
                ).expect("can deserialize")),
                epoch: MerkleEpoch::new(0),
            }],
            Arc::clone(&config),
        )?);
        let vk = File::open(&config.user_verification_key_path)?;
        let vk: Groth16VerificationKey = serde_json::from_reader(vk)?;
        let oprf_service =
            OprfService::init(Arc::clone(&config), crypto_device, chain_watcher, vk.into());
        let server = api::new_test_app(config, PartyId::from(0), oprf_service);
        Ok(server)
    }

    fn init_req() -> serde_json::Value {
        serde_json::json!({
          "request_id": "598bbf10-5c8c-484d-a6a8-797df2f6adad",
          "proof": {
            "pi_a": [
              "14950137340857000683222569762333765310473881853005116566045546314594839239598",
              "11775569493808639561638425283898899249711410214638629000366143416753426284589",
              "1"
            ],
            "pi_b": [
              [
                "2785514216536277469827906089473581593816545804542544051984432397533886084626",
                "17930103312496396226353435195950919235360268218173249660508137011847990329751"
              ],
              [
                "2363689777289495504064683516501778916746070898103709476778676066463296842685",
                "6941075786901911120599789621029487052766435115468727654164762473724024343868"
              ],
              [
                "1",
                "0"
              ]
            ],
            "pi_c": [
              "14917417826074216436678528082272805526100515653647889683876810571053982674852",
              "18095770844934730928017558660041137777286354566190867165301998237933752732866",
              "1"
            ]
          },
          "point_b": [
            "17545216781400172894265373183007675673600726709015686814609433516294328685361",
            "4537764014265182053143850536234521610551807474914555869615963094641400823793"
          ],
          "rp_identifier": {
            "rp_id": 0,
            "key_epoch": 0
          },
          "merkle_epoch": 0,
          "action": "1120809321026975175757466560999318768049435153540642913185613570219065846805",
          "nonce": "11995758882934032369948628586537618022736362526028373754122425120894302910697",
          "signature": "246F7FB4040A520C17D4358883A5103FA43483EA12C8039BADE1CFBF2CAAF2FE56DE7C9B833EE0F52C3E9F99C50D3E328B25211B146AB5F28B9055329A323FE3",
          "cred_pk": {
            "pk": [
              "20250441087630822051897171877168864569957088175290736110746783269969005217521",
              "2413711181075542609538861548035891129041376599307510529757411775315152595154"
            ]
          },
          "current_time_stamp": "650588418409228923"
        })
    }

    fn finish_req() -> serde_json::Value {
        serde_json::json!({
            "request_id": "598bbf10-5c8c-484d-a6a8-797df2f6adad",
            "challenge": {
              "e": "16620368534569496780871678850089758319969215860113286164642302138248101420004"
            },
            "rp_identifier": {
              "rp_id": 0,
              "key_epoch": 0
            }
        })
    }

    #[tokio::test]
    async fn test_init() -> eyre::Result<()> {
        let server = test_server().await?;
        let req = init_req();
        server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_bad_proof() -> eyre::Result<()> {
        let server = test_server().await?;
        let mut req = init_req();
        req["proof"]["pi_a"] = req["proof"]["pi_c"].clone();
        let res = server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("invalid proof");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_bad_signature() -> eyre::Result<()> {
        let server = test_server().await?;
        let mut req = init_req();
        req["signature"] = serde_json::json!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        let res = server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("Invalid signature: signature error");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_invalid_point() -> eyre::Result<()> {
        let server = test_server().await?;
        let mut req = init_req();
        req["point_b"] = serde_json::json!("0");
        server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await
            .assert_status_unprocessable_entity();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish() -> eyre::Result<()> {
        let server = test_server().await?;
        let req = init_req();
        server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        let req = finish_req();
        server
            .post("/api/v1/finish")
            .json(&req)
            .await
            .assert_status_ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish_without_init() -> eyre::Result<()> {
        let server = test_server().await?;
        let req = finish_req();
        server
            .post("/api/v1/finish")
            .json(&req)
            .expect_failure()
            .await
            .assert_status_not_found();
        Ok(())
    }
}
