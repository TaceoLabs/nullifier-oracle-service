use std::process::ExitCode;

use clap::Parser;
use oprf_service::config::OprfPeerConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    let tracing_config = nodes_telemetry::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_telemetry::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();
    tracing::info!("{}", oprf_service::version_info());
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let result = oprf_service::start(
        OprfPeerConfig::parse(),
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
