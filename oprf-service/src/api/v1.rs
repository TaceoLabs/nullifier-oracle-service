//! Version 1 (v1) API Routes
//!
//! This module defines the v1 API routes for the OPRF peer service.
//! Currently, all endpoints are unauthenticated. Routes are structured under `/oprf`.
//!
//! It also applies a restrictive CORS policy suitable for JSON-based POST requests.
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub(crate) mod oprf;

use crate::AppState;

/// Builds unauthenticated routes for the service.
///
/// Currently all requests are unauthenticated. The routes are defined in the `oprf` module.
fn unauthenticated_routes() -> Router<AppState> {
    oprf::router()
}

/// Build the v1 API router.
///
/// This sets up:
/// - `/oprf` routes
/// - health endpoints (`/health`, `/ready`, `/live`)
/// - a restrictive CORS layer allowing JSON POST requests and OPTIONS preflight and a wildcard origin.
///
/// # Arguments
///
/// * `input_max_body_limit` - maximum allowed size of request bodies in bytes.
pub(crate) fn build() -> Router<AppState> {
    // We setup a wildcard as we are a public API and everyone can access the service.
    let cors = CorsLayer::new()
        .allow_credentials(false)
        .allow_headers([http::header::CONTENT_TYPE, http::header::USER_AGENT])
        .allow_methods([http::Method::POST, http::Method::OPTIONS])
        .allow_origin(AllowOrigin::any());
    Router::new().merge(unauthenticated_routes()).layer(cors)
}
