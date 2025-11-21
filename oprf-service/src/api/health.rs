//! Health Check Endpoints
//!
//! This module defines the health endpoint for the OPRF peer API.
//! These endpoints provide simple HTTP status responses to indicate the service's status.
//!
//! - `/health` – general health check
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tower_http::set_header::SetResponseHeaderLayer;

/// Create a router containing the health endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes() -> Router {
    Router::new()
        .route("/health", get(health))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// General health check endpoint.
///
/// Returns `200 OK` with a plain `"healthy"` response.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "healthy")
}
