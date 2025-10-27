//! Info Endpoint
//!
//! Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
//!
//! - `/info` – general info about the deployment
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

/// Create a router containing the info endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/info", get(info))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// Responds with cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
///
/// Returns `200 OK` with a string response.
async fn info(State(_app_state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok((StatusCode::OK, super::super::version_info()))
}
