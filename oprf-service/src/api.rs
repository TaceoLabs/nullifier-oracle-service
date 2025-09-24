//! API module for the OPRF peer service.
//!
//! This module defines all HTTP endpoints exposed by the OPRF peer and organizes them into submodules:
//!
//! - [`errors`] – Defines API error types and conversions from internal service errors.
//! - [`health`] – Provides health, readiness, and liveness endpoints (`/health`, `/ready`, `/live`).
//! - [`v1`] – Version 1 of the main OPRF endpoints, including `/oprf/init` and `/oprf/finish`.
//!
//! The `api` module uses `axum` for routing and request handling, and all routes are designed to be stateless,
//! forwarding requests to the appropriate service (`OprfService`, `ChainWatcherService`, etc.).

use std::sync::Arc;

use axum::Router;
use oprf_types::crypto::PartyId;
use tower_http::trace::TraceLayer;

use crate::{AppState, config::OprfPeerConfig, services::oprf::OprfService};

#[cfg(test)]
use axum_test::TestServer;

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod v1;

/// Builds the main API router for the OPRF peer service.
///
/// This function sets up:
///
/// - The `/api/v1` endpoints from [`v1`].
/// - The health and readiness endpoints from [`health`].
/// - An HTTP trace layer via [`TraceLayer`].
///
/// The returned [`Router`] has an [`AppState`] attached that contains the configuration and service
/// instances needed to handle requests.
pub(crate) fn new_app(
    config: Arc<OprfPeerConfig>,
    party_id: PartyId,
    oprf_service: OprfService,
) -> Router {
    let app_state = AppState {
        config: Arc::clone(&config),
        oprf_service,
        party_id,
    };
    Router::new()
        .nest("/api/v1", v1::build(config.input_max_body_limit))
        .merge(health::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Builds a [`TestServer`] with the same configuration as [`new_app`].
///
/// This function is only compiled in tests (`#[cfg(test)]`) and provides a convenient way
/// to spin up the full API with mock services and expectations.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn new_test_app(
    config: Arc<OprfPeerConfig>,
    party_id: PartyId,
    oprf_service: OprfService,
) -> TestServer {
    let app = new_app(config, party_id, oprf_service);
    TestServer::builder()
        .expect_success_by_default()
        .mock_transport()
        .build(app)
        .unwrap()
}
