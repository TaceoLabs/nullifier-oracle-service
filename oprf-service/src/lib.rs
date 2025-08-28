#![warn(missing_docs)]
use std::sync::Arc;

use axum::{Router, extract::FromRef};
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::config::ServiceConfig;

mod api;
pub mod config;
pub mod metrics;
pub mod telemetry;

#[derive(Clone)]
pub(crate) struct AppState {
    pub config: Arc<ServiceConfig>,
}
impl FromRef<AppState> for Arc<ServiceConfig> {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.config)
    }
}

pub async fn start(
    config: config::ServiceConfig,
    shutdown_signal: impl std::future::Future<Output = ()>,
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
    tracing::debug!("startig with config: {config:#?}");
    let config = Arc::new(config);

    let cancellation_token = CancellationToken::new();

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let app_state = AppState { config };
    let axum_rest_api = api::v1::build(app_state);

    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_result = axum::serve(listener, axum_rest_api)
            .with_graceful_shutdown(async move { axum_cancel_token.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
    });
    tracing::info!("everything started successfully - now waiting for shutdown...");
    wait_for_shutdown(cancellation_token, shutdown_signal).await;

    // TODO: implement graceful shutdown for services that need it
    // let shutdown_timeout = config.max_wait_time_shutdown;
    // tracing::info!(
    //     "shutting down CCL. Max wait time {} seconds",
    //     shutdown_timeout.as_secs()
    // );
    // let shutdown_result = tokio::time::timeout(shutdown_timeout, async move {
    //     tokio::join!(server, worker_join_handle)
    // })
    // .await;
    // match shutdown_result {
    //     Ok(_) => {
    //         tracing::info!("successfully shutdown CCL");
    //     }
    //     Err(_) => {
    //         tracing::warn!("could not shutdown CCL in provided wait time. We die now.");
    //     }
    // }
    Ok(())
}

async fn wait_for_shutdown(
    cancellation_token: CancellationToken,
    shutdown_signal: impl Future<Output = ()>,
) {
    tokio::select! {
        _ = cancellation_token.cancelled() => {
            tracing::info!("received manual shutdown signal - triggering shutdown");
        }
        _ = shutdown_signal => {
            tracing::info!("received SIGTERM - trigger external shutdown");
            cancellation_token.cancel();
        },
    }
}

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
