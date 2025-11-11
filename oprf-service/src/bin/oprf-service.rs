//! OPRF Service Binary
//!
//! This is the main entry point for the OPRF peer service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use clap::Parser;
use oprf_service::{AwsSecretManager, config::OprfPeerConfig};

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    let tracing_config = nodes_telemetry::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_telemetry::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();
    tracing::info!("{}", oprf_service::version_info());
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let config = OprfPeerConfig::parse();
    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        AwsSecretManager::init(
            &config.rp_secret_id_prefix,
            &config.wallet_private_key_secret_id,
            config.environment,
        )
        .await,
    );

    let result = oprf_service::start(
        config,
        secret_manager,
        oprf_service::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            // we don't want to double print the error therefore we just return FAILURE
            tracing::error!("{err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}
