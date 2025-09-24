//! v1 OPRF Routes
//!
//! This module defines the OPRF endpoints for version 1 of the API.
//!
//! # Endpoints
//!
//! - `POST /init` – Initializes an OPRF session and commits to the partial exponent.
//! - `POST /finish` – Completes the OPRF session and returns the proof share.
//!
//! Both endpoints use the [`OprfService`] for application logic.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use tracing::instrument;

use crate::{
    AppState,
    api::errors::{ApiErrors, ApiResult},
    services::oprf::OprfService,
};

/// Handles `POST /init`.
///
/// Validates the nonce signature, retrieves the relevant merkle root for the requested epoch,
/// and initializes a new OPRF session via [`OprfService`].
#[instrument(level = "debug", skip_all)]
async fn oprf_request(
    State(oprf_service): State<OprfService>,
    Json(request): Json<OprfRequest>,
) -> ApiResult<Json<OprfResponse>> {
    tracing::debug!("received new OPRF request: {request:?}");
    let request_id = request.request_id;

    tracing::debug!("verify nonce signature");
    if !request.rp_pk.verify(request.nonce, &request.signature) {
        tracing::debug!("failed to verify nonce signature");
        return Err(ApiErrors::BadRequest(
            "failed to verify nonce signature".to_string(),
        ));
    }
    let commitments = oprf_service.init_oprf_session(request).await?;
    Ok(Json(OprfResponse {
        request_id,
        commitments,
    }))
}

/// Handles `POST /finish`.
///
/// Finalizes the OPRF session for the given request and returns the resulting proof share.
#[instrument(level = "debug", skip_all)]
async fn oprf_challenge(
    State(oprf_service): State<OprfService>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    tracing::debug!("received Challenge for request: {request:?}");
    let request_id = request.request_id;
    // Finalize the OPRF session
    let proof_share = oprf_service.finalize_oprf_session(request)?;
    Ok(Json(ChallengeResponse {
        request_id,
        proof_share,
    }))
}

/// Builds the router for v1 OPRF endpoints.
///
/// # Arguments
///
/// * `input_max_body_limit` - Maximum allowed body size for requests in bytes.
pub(crate) fn router(input_max_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/init", post(oprf_request))
        .route("/finish", post(oprf_challenge))
        .layer(DefaultBodyLimit::max(input_max_body_limit))
}
