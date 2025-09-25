use std::process::ExitCode;

use clap::Parser;
use git_version::git_version;
use oprf_service::config::OprfPeerConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    let tracing_config = nodes_telemetry::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_telemetry::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();
    tracing::info!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version!(fallback = "UNKNOWN"))
    );

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
