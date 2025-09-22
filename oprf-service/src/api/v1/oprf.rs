use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use tracing::instrument;

use crate::{
    AppState, api::errors::ApiErrors, services::chain_watcher::ChainWatcherService,
    services::oprf::OprfService,
};

type ApiResult<T> = Result<T, ApiErrors>;

/// Inits an OPRF session.
///
/// Deserializes the request and forwards the parsed request to the [`OprfService`] to create the session and commit to the partial exponent.
#[instrument(level = "debug", skip_all)]
async fn oprf_request(
    State(oprf_service): State<OprfService>,
    State(chain_watcher): State<ChainWatcherService>,
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
    // get the merkle root identified by the epoch
    let _merkle_root = chain_watcher.get_merkle_root_by_epoch(request.merkle_epoch);
    // TODO compare merkle root of request with cache and/or chain
    // Init the OPRF session
    let commitments = oprf_service.init_oprf_session(request)?;
    Ok(Json(OprfResponse {
        request_id,
        commitments,
    }))
}

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

pub(crate) fn router(input_max_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/init", post(oprf_request))
        .route("/finish", post(oprf_challenge))
        .layer(DefaultBodyLimit::max(input_max_body_limit))
}
