//! OPRF Service Binary
//!
//! This is the main entry point for the OPRF peer service.
//! It initializes tracing, metrics, and starts the service with configuration
//! from command-line arguments or environment variables.

use std::{process::ExitCode, sync::Arc};

use aws_config::Region;
use aws_sdk_secretsmanager::config::Credentials;
use clap::Parser;
use oprf_service::{
    AwsSecretManager,
    config::{self, OprfPeerConfig},
};

async fn load_aws_config(environment: config::Environment) -> aws_config::SdkConfig {
    match environment {
        config::Environment::Prod => {
            tracing::info!("initializing AWS secret manager from env...");
            aws_config::load_from_env().await
        }
        config::Environment::Dev => {
            tracing::info!("using localstack config");
            let region_provider = Region::new("us-east-1");
            let credentials = Credentials::new("test", "test", None, None, "Static");
            // in case we don't want the standard url, we can configure it via the environment
            aws_config::from_env()
                .region(region_provider)
                .endpoint_url(
                    std::env::var("TEST_AWS_ENDPOINT_URL")
                        .unwrap_or("http://localhost:4566".to_string()),
                )
                .credentials_provider(credentials)
                .load()
                .await
        }
    }
}

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

    let aws_config = load_aws_config(config.environment).await;

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        AwsSecretManager::init(
            aws_config,
            &config.rp_secret_id_prefix,
            &config.wallet_private_key_secret_id,
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
