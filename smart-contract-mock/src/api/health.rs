//! Health Check Endpoints
//!
//! This module defines the health, readiness, and liveness endpoints for the OPRF peer API.
//! These endpoints provide simple HTTP status responses to indicate the service's status.
//!
//! - `/health` – general health check
//! - `/ready` – readiness check (service ready to handle requests)
//! - `/live` – liveness check (service is alive)
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use axum::{
    Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::AppState;

use super::errors::ApiError;

/// Create a router containing the health endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/live", get(live))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// General health check endpoint.
///
/// Returns `200 OK` with a plain `"healthy"` response.
async fn health(State(_app_state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok((StatusCode::OK, "healthy"))
}

/// Readiness endpoint.
///
/// Returns `200 OK` with `"ready"`. In future, may check internal service state.
async fn ready(State(_register): State<AppState>) -> impl IntoResponse {
    // TODO: detect from register if service is ready?
    (StatusCode::OK, "ready")
}

/// Liveness endpoint.
///
/// Returns `200 OK` with `"live"` indicating the service is running.
async fn live() -> impl IntoResponse {
    (StatusCode::OK, "live")
}
