//! API module for the OPRF node service.
//!
//! This module defines all HTTP endpoints an OPRF node must serve to participate in TACEO:Oprf and organizes them into submodules:
//!
//! - [`errors`] – Defines API error types and conversions from internal service errors.
//! - [`health`] – Provides health endpoints (`/health`).
//! - [`info`] – Info about the service (`/version` and `/wallet`).
//! - [`v1`] – Version 1 of the main OPRF endpoints, including `/init` and `/finish`.

use alloy::primitives::Address;
use axum::{Router, response::IntoResponse};
use serde::de::DeserializeOwned;
use tower_http::trace::TraceLayer;

use crate::{OprfRequestAuthService, services::oprf::OprfService};

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod info;
pub(crate) mod v1;

/// Builds the main API router for the OPRF node service.
///
/// This function sets up:
///
/// - The `/api/v1` endpoints from [`v1`].
/// - The health and readiness endpoints from [`health`].
/// - General info about the deployment from [`info`].
/// - An HTTP trace layer via [`TraceLayer`].
///
/// The returned [`Router`] can be incorporated into another router or be served directly by axum. Implementations don't need to configure anything in their `State`, the service is inlined as [`Extension`](https://docs.rs/axum/latest/axum/struct.Extension.html).
pub fn routes<
    RequestAuth: DeserializeOwned + Send + 'static,
    RequestAuthError: IntoResponse + 'static,
>(
    oprf_service: OprfService,
    req_auth_service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
    wallet_address: Address,
) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            v1::routes(oprf_service.clone(), req_auth_service),
        )
        .merge(health::routes())
        .merge(info::routes(oprf_service.clone(), wallet_address))
        .layer(TraceLayer::new_for_http())
}
