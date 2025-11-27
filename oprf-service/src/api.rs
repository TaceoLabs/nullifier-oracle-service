//! API module for the OPRF peer service.
//!
//! This module defines all HTTP endpoints an OPRF peer must serve to participate in TACEO:Oprf and organizes them into submodules:
//!
//! - [`errors`] – Defines API error types and conversions from internal service errors.
//! - [`health`] – Provides health endpoints (`/health`).
//! - [`info`] – Info about the service (`/version` and `/wallet`).
//! - [`v1`] – Version 1 of the main OPRF endpoints, including `/init` and `/finish`.

use crate::{OprfRequestAuthService, oprf_key_material_store::OprfKeyMaterialStore};
use alloy::primitives::Address;
use axum::Router;
use oprf_types::crypto::PartyId;
use serde::Deserialize;
use std::time::Duration;
use tower_http::trace::TraceLayer;

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod info;
pub(crate) mod v1;

/// Builds the main API router for the OPRF peer service.
///
/// This function sets up:
///
/// - The `/api/v1/oprf` endpoint from [`v1`].
/// - The health and readiness endpoints from [`health`].
/// - General info about the deployment from [`info`].
/// - An HTTP trace layer via [`TraceLayer`].
///
/// The returned [`Router`] can be incorporated into another router or be served directly by axum. Implementations don't need to configure anything in their `State`, the service is inlined as [`Extension`](https://docs.rs/axum/latest/axum/struct.Extension.html).
pub fn routes<
    RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
    RequestAuthError: Send + 'static + std::error::Error,
>(
    party_id: PartyId,
    oprf_material_store: OprfKeyMaterialStore,
    req_auth_service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
    wallet_address: Address,
    max_message_size: usize,
    max_connection_lifetime: Duration,
) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            v1::routes(
                party_id,
                oprf_material_store.clone(),
                req_auth_service.clone(),
                max_message_size,
                max_connection_lifetime,
            ),
        )
        .merge(health::routes())
        .merge(info::routes(oprf_material_store.clone(), wallet_address))
        .layer(TraceLayer::new_for_http())
}
