use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    AppState,
    api::errors::ApiErrors,
    services::oprf::{FinalizeOprfSessionRequestn, InitOprfSessionRequest, OprfService},
};

type ApiResult<T> = Result<T, ApiErrors>;

#[derive(Debug, Deserialize)]
pub struct OprfRequest {
    pub request_id: Uuid,
    pub user_proof: String,
    pub point_a: String,
}

#[derive(Debug, Serialize)]
pub struct OprfResponse {
    pub request_id: Uuid,
    pub response: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub request_id: Uuid,
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub request_id: Uuid,
    pub proof_share: String,
}

#[instrument(level = "debug", name = "oprf", skip_all)]
/// Inits an OPRF session.
///
/// Deserializes the request and forwards the parsed request to the [`OprfService`] to create the session and commit to the partial exponent.
async fn oprf_request(
    State(oprf_service): State<OprfService>,
    Json(request): Json<OprfRequest>,
) -> ApiResult<Json<OprfResponse>> {
    tracing::debug!("received new OPRF request: {request:?}");
    let request_id = request.request_id;
    // Parses the request
    let request = InitOprfSessionRequest::try_from(request)?;
    // Init the OPRF session
    let response = oprf_service.init_oprf_session(request)?;
    Ok(Json(OprfResponse {
        request_id,
        response,
    }))
}

async fn oprf_challenge(
    State(oprf_service): State<OprfService>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    tracing::debug!("received Challenge for request: {request:?}");
    let request_id = request.request_id;
    // Parse the request
    let challenge = FinalizeOprfSessionRequestn::try_from(request)?;
    // Finalize the OPRF session
    let proof_share = oprf_service.finalize_oprf_session(challenge)?;
    Ok(Json(ChallengeResponse {
        request_id,
        proof_share,
    }))
}

pub(crate) fn router(input_max_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/init", post(oprf_request))
        .route("/finish", post(oprf_challenge))
        .layer(DefaultBodyLimit::max(input_max_body_limit))
}
