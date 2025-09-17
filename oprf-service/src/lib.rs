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
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::{
    config::OprfPeerConfig,
    services::{
        chain_watcher::ChainWatcherService, crypto_device::CryptoDevice,
        event_handler::ChainEventHandler, oprf::OprfService, secret_manager,
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
    chain_watcher: ChainWatcherService,
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

impl FromRef<AppState> for ChainWatcherService {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.chain_watcher)
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
    #[cfg(feature = "file-secret-manager")]
    let secret_manager = secret_manager::local::init().await;
    #[cfg(not(feature = "file-secret-manager"))]
    let secret_manager = secret_manager::aws::init(Arc::clone(&config)).await;

    // TODO load all RP_ids from SC

    tracing::info!("init crypto device..");
    let crypto_device = Arc::new(
        CryptoDevice::init(secret_manager, vec![])
            .await
            .context("while initiating crypto-device")?,
    );

    // start oprf-service service
    tracing::info!("init oprf-service...");
    let oprf_service =
        OprfService::init(Arc::clone(&config), Arc::clone(&crypto_device), vk.into());

    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    tracing::info!("spawn chain watcher..");
    // spawn the chain watcher
    let chain_watcher = services::chain_watcher::init(
        Arc::clone(&config),
        Arc::clone(&crypto_device),
        cancellation_token.clone(),
    );

    tracing::info!("spawning chain event handler..");
    // spawn the periodic task
    let event_handler = ChainEventHandler::spawn(
        config.chain_check_interval,
        chain_watcher.clone(),
        Arc::clone(&crypto_device),
        cancellation_token.clone(),
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    let axum_rest_api = api::new_app(Arc::clone(&config), oprf_service, chain_watcher);

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
    use std::{path::PathBuf, time::Duration};

    use axum_test::TestServer;

    use crate::config::Environment;

    use super::*;

    async fn test_server() -> eyre::Result<TestServer> {
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
            private_key_secret_id: "orpf/sk".to_string(),
            dlog_share_secret_id_suffix: "oprf/shares/".to_string(),
        };
        let _config = Arc::new(config);
        todo!()
        // let secret_manager = secret_manager::local::init()?;
        // let crypto_device = Arc::new(CryptoDevice::init(secret_manager, Vec::new()).await?);
        // let vk = File::open(&config.user_verification_key_path)?;
        // let vk: Groth16VerificationKey = serde_json::from_reader(vk)?;
        // let oprf_service = OprfService::init(Arc::clone(&config), crypto_device, vk.into());

        // let chain_watcher = crate::services::chain_watcher::init(
        //     Arc::clone(&config),
        //     Arc::clone(&crypto_device),
        //     CancellationToken::new(),
        // );
        // let server = api::new_test_app(config, oprf_service, chain_watcher);
        // Ok(server)
    }

    fn init_req() -> serde_json::Value {
        serde_json::json!({
            "request_id": "e70268aa-fa9a-4e9e-b76c-c41fff40f6f4",
            "proof": {
              "pi_a": [
                "6349570088365552239612347468351610627195030363513293827443377303359660823669",
                "6753883411263494317944303627097592155325952374143787573092555378760696609897",
                "1"
              ],
              "pi_b": [
                [
                  "1029525447704954470968997867751954950530344967964073379148935357546227680429",
                  "871118679697810306823762821446145694919635208444599225201223171537142303434"
                ],
                [
                  "17386501546121704623661895573517623371232645240102206072482573194074052902929",
                  "9162154086687477089722341440812693001637734641073250904213144361349375807542"
                ],
                [
                  "1",
                  "0"
                ]
              ],
              "pi_c": [
                "4290638307091560008359938510617691693837093003791342827618304777208210686605",
                "11122274897539367157049285256126542704142033744794859131294844414789776803491",
                "1"
              ]
            },
            "point_b": [
              "18237229852531934280679321339995874890383597479740627110845247919555047357510",
              "3668425390394053707146876594874500621838710739979860432809555286424756824931"
            ],
            "rp_key_id": {
              "rp_id": 0,
              "key_epoch": 0
            },
            "merkle_epoch": 0,
            "merkle_root": "18113525670981476624162220635029909626458587036860423708002025726733198978273",
            "action": "4780594342984269312659834610742751871778649094924684591207098796086938056455",
            "nonce": "16526427576321170906618500040054521043441986479477002208590768728741775635002",
            "signature": {
              "r": [
                "1051127582116816098464922787683501458236668706209853015557519330864147549639",
                "16375937591535146361037884689273654078836000169295135357191197962801711293702"
              ],
              "s": "2367218161840642687877915404264974575293885020472239903684633479580936117917"
            },
            "rp_pk": {
              "pk": [
                "10265072520302061766783430308667681143731174197023564349371614639508988107811",
                "9343021272028152424050964465457090846274804108161787027537058016585155190409"
              ]
            }
        })
    }

    fn finish_req() -> serde_json::Value {
        serde_json::json!({
            "request_id": "e70268aa-fa9a-4e9e-b76c-c41fff40f6f4",
            "challenge": {
              "e": "16620368534569496780871678850089758319969215860113286164642302138248101420004"
            },
            "rp_key_id": {
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
        req["signature"]["s"] = serde_json::json!("1234");
        let res = server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("failed to verify nonce signature");
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
