//! Info Endpoint
//!
//! Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
//!
//! - `/version` – returns the version string
//! - `/wallet` – returns the wallet address
//! - `/rp/{rp_id}` – returns the [`oprf_types::api::v1::PublicRpMaterial`] associated with the [`RpId`] iff the OPRF peer has the information stored.
//!
//! The endpoints include a `Cache-Control: no-cache` header to prevent caching of responses.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use oprf_types::RpId;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{AppState, services::oprf::OprfService};

/// Create a router containing the info endpoints.
///
/// All endpoints have `Cache-Control: no-cache` set.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/version", get(version))
        .route("/wallet", get(wallet))
        .route("/rp/{rp_id}", get(rp_available))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// Responds with cargo package name, cargo package version, and the git hash of the repository that was used to build the binary
///
/// Returns `200 OK` with a string response.
async fn version(State(_app_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, crate::version_info())
}

/// Responds with the wallet address of the oprf peer
///
/// Returns `200 OK` with a string response.
async fn wallet(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, state.wallet_address.to_string())
}

/// Checks whether a RP associated with the [`RpId`] is registered at the service.
///
/// Returns `200 OK` with [`oprf_types::api::v1::PublicRpMaterial`] from the RP if registered.
/// Returns `404 Not Found` if not registered.
async fn rp_available(
    State(oprf_service): State<OprfService>,
    Path(rp_id): Path<RpId>,
) -> impl IntoResponse {
    if let Some(public_material) = oprf_service.rp_material_store.get_rp_public_material(rp_id) {
        (StatusCode::OK, Json(public_material)).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
