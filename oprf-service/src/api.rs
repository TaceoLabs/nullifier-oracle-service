use std::sync::Arc;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::{
    AppState,
    config::OprfConfig,
    services::{chain_watcher::ChainWatcherService, oprf::OprfService},
};

#[cfg(test)]
use axum_test::TestServer;

pub mod errors;
pub mod health;
pub mod v1;

pub(crate) fn new_app(
    config: Arc<OprfConfig>,
    oprf_service: OprfService,
    chain_watcher: ChainWatcherService,
) -> Router {
    let app_state = AppState {
        config: Arc::clone(&config),
        oprf_service,
        chain_watcher,
    };
    Router::new()
        .nest("/api/v1", v1::build(config.input_max_body_limit))
        .merge(health::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

#[cfg(test)]
pub(crate) fn new_test_app(
    config: Arc<OprfConfig>,
    oprf_service: OprfService,
    chain_watcher: ChainWatcherService,
) -> TestServer {
    let app = new_app(config, oprf_service, chain_watcher);
    TestServer::builder()
        .expect_success_by_default()
        .mock_transport()
        .build(app)
        .unwrap()
}
