use std::sync::Arc;

use axum::{Router, extract::FromRef};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;

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

/// Main entry point for the OPRF-Service. Parsed the config and spins up all necessary services.
/// TODO better docs
pub async fn start(
    config: config::ServiceConfig,
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
    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let app_state = AppState {
        config: Arc::clone(&config),
    };

    let axum_rest_api = Router::new()
        .nest("/api/v1", api::v1::build(config.input_max_body_limit))
        .merge(api::health::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

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
    cancellation_token.cancelled().await;
    tracing::info!(
        "waiting for shutdown of services (max wait time {} as secs)..",
        config.max_wait_time_shutdown.as_secs()
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, server).await {
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
