//! Version 1 (v1) API Routes
//!
//! This module defines the v1 API routes for the OPRF node service.
//! Currently, all endpoints are unauthenticated.
//! # Endpoints
//!
//! - `POST /init` – Initializes an OPRF session and commits to the partial exponent.
//! - `POST /finish` – Completes the OPRF session and returns the proof share.

use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use serde::Deserialize;
use tracing::instrument;

use crate::{OprfRequestAuthService, services::oprf::OprfService};

/// Handles `POST /init`.
///
/// Validates the nonce signature, retrieves the relevant merkle root for the requested epoch,
/// and initializes a new OPRF session via [`OprfService`].
#[instrument(level = "debug", skip_all, fields(request_id=%request.request_id))]
async fn oprf_request<RequestAuth, RequestAuthError: IntoResponse>(
    Extension(oprf_service): Extension<OprfService>,
    Extension(oprf_req_auth_service): Extension<
        OprfRequestAuthService<RequestAuth, RequestAuthError>,
    >,
    Json(request): Json<OprfRequest<RequestAuth>>,
) -> axum::response::Result<Json<OprfResponse>> {
    tracing::debug!("received new oprf request: {request:?}");
    let request_id = request.request_id;
    let party_id = oprf_service.party_id;
    tracing::debug!("verifying request auth...");
    oprf_req_auth_service.verify(&request).await?;
    let commitments = oprf_service
        .init_oprf_session(request_id, request.share_identifier, request.blinded_query)
        .await?;
    Ok(Json(OprfResponse {
        request_id,
        commitments,
        party_id,
    }))
}

/// Handles `POST /finish`.
///
/// Finalizes the OPRF session for the given request and returns the resulting proof share.
#[instrument(level = "debug", skip_all, fields(request_id=%request.request_id))]
async fn oprf_challenge(
    Extension(oprf_service): Extension<OprfService>,
    Json(request): Json<ChallengeRequest>,
) -> axum::response::Result<Json<ChallengeResponse>> {
    tracing::debug!("received challenge request: {request:?}");
    let request_id = request.request_id;
    let proof_share = oprf_service.finalize_oprf_session(request)?;
    Ok(Json(ChallengeResponse {
        request_id,
        proof_share,
    }))
}

/// Builds the router for v1 OPRF endpoints.
pub fn routes<
    RequestAuth: for<'de> Deserialize<'de> + Send + 'static,
    RequestAuthError: IntoResponse + 'static,
>(
    oprf_service: OprfService,
    req_auth_service: OprfRequestAuthService<RequestAuth, RequestAuthError>,
) -> Router {
    Router::new()
        .route("/init", post(oprf_request::<RequestAuth, RequestAuthError>))
        .route("/finish", post(oprf_challenge))
        .layer(Extension(req_auth_service))
        .layer(Extension(oprf_service))
}
