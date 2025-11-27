//! Info Endpoint
//!
//! Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
//!
//! - `/version` – returns the version string
//! - `/wallet` – returns the wallet address
//! - `/oprf_pub/{id}` – returns the [`oprf_types::crypto::OprfPublicKey`] associated with the [`OprfKeyId`] if the OPRF node has the information stored.
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use alloy::primitives::Address;
use axum::{
    Extension, Json, Router,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use oprf_types::OprfKeyId;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::oprf_key_material_store::OprfKeyMaterialStore;

/// Create a router containing the info endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes(oprf_material_store: OprfKeyMaterialStore, wallet_address: Address) -> Router {
    Router::new()
        .route("/version", get(version))
        .route("/wallet", get(move || wallet(wallet_address)))
        .route("/oprf_pub/{id}", get(oprf_key_available))
        .layer(Extension(oprf_material_store))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// Responds with cargo package name, cargo package version, and the git hash of the repository that was used to build the binary.
///
/// Returns `200 OK` with a string response.
async fn version() -> impl IntoResponse {
    (StatusCode::OK, crate::version_info())
}

/// Responds with the wallet address of the oprf node
///
/// Returns `200 OK` with a string response.
async fn wallet(wallet_address: Address) -> impl IntoResponse {
    (StatusCode::OK, wallet_address.to_string())
}

/// Checks whether a OPRF public-key associated with the [`OprfKeyId`] is registered at the service.
///
/// Returns `200 OK` with [`oprf_types::crypto::OprfPublicKey`].
/// Returns `404 Not Found` if not registered.
async fn oprf_key_available(
    Extension(oprf_material_store): Extension<OprfKeyMaterialStore>,
    Path(id): Path<OprfKeyId>,
) -> impl IntoResponse {
    if let Some(public_material) = oprf_material_store.get_oprf_public_key(id) {
        (StatusCode::OK, Json(public_material)).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
