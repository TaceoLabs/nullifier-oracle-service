use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use tracing::instrument;

use crate::{
    AppState,
    api::errors::ApiErrors,
    services::oprf::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse, OprfService},
};

type ApiResult<T> = Result<T, ApiErrors>;

/// Inits an OPRF session.
///
/// Deserializes the request and forwards the parsed request to the [`OprfService`] to create the session and commit to the partial exponent.
#[instrument(level = "debug", name = "oprf", skip_all)]
async fn oprf_request(
    State(oprf_service): State<OprfService>,
    Json(request): Json<OprfRequest>,
) -> ApiResult<Json<OprfResponse>> {
    tracing::debug!("received new OPRF request: {request:?}");
    let request_id = request.request_id;
    // Init the OPRF session
    let commitments = oprf_service.init_oprf_session(request)?;
    Ok(Json(OprfResponse {
        request_id,
        commitments,
    }))
}

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

pub(crate) fn router(input_max_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/init", post(oprf_request))
        .route("/finish", post(oprf_challenge))
        .layer(DefaultBodyLimit::max(input_max_body_limit))
}
