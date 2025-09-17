use clap::Parser as _;
use git_version::git_version;
use smart_contract_mock::config::SmartContractMockConfig;
use tokio::signal;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("smart_contract_mock=trace,warn"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // TODO setup DD logging - put this in a common crate
    install_tracing();
    tracing::info!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version!(fallback = "UNKNOWN"))
    );

    let result =
        smart_contract_mock::start(SmartContractMockConfig::parse(), default_shutdown_signal())
            .await;
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
