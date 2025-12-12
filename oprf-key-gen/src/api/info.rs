//! Info Endpoint
//!
//! Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
//!
//! - `/version` – returns the version string
//! - `/wallet` – returns the wallet address
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use alloy::primitives::Address;
use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tower_http::set_header::SetResponseHeaderLayer;

/// Create a router containing the info endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes(wallet_address: Address) -> Router {
    Router::new()
        .route("/version", get(version))
        .route("/wallet", get(move || wallet(wallet_address)))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// Responds with cargo package name, cargo package version, and the git hash of the repository that was used to build the binary.
///
/// Returns `200 OK` with a string response.
async fn version() -> impl IntoResponse {
    (StatusCode::OK, nodes_common::version_info())
}

/// Responds with the wallet address of the oprf key gen instance.
///
/// Returns `200 OK` with a string response.
async fn wallet(wallet_address: Address) -> impl IntoResponse {
    (StatusCode::OK, wallet_address.to_string())
}
