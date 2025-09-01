use clap::Parser;
use git_version::git_version;
use oprf_service::config::OprfConfig;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let tracing_config = oprf_service::telemetry::ServiceConfig::try_from_env()?;
    let _tracing_handle = oprf_service::telemetry::initialize_tracing(&tracing_config)?;
    oprf_service::metrics::describe_metrics();
    tracing::info!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version!(fallback = "UNKNOWN"))
    );

    let result =
        oprf_service::start(OprfConfig::parse(), oprf_service::default_shutdown_signal()).await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(())
        }
        Err(err) => {
            tracing::error!("{err:?}");
            Err(err)
        }
    }
}
