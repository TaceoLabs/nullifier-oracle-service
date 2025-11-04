//! Version 1 (v1) API Routes
//!
//! This module defines the v1 API routes for the OPRF peer service.
//! Currently, all endpoints are unauthenticated.
use axum::Router;

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
/// - `oprf` routes
pub(crate) fn build() -> Router<AppState> {
    Router::new().merge(unauthenticated_routes())
}
