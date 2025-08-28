use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{AppState, api::errors::ApiError, config::ServiceConfig};

#[derive(Debug, Deserialize)]
pub struct OprfRequest {
    pub job_id: Uuid,
    // TODO
    pub request: String,
}

#[derive(Debug, Serialize)]
pub struct OprfResponse {
    pub job_id: Uuid,
    // TODO
    pub response: String,
}

#[instrument(level = "info", name = "oprf", skip_all)]
/// create a new job
async fn oprf_request(
    State(_config): State<Arc<ServiceConfig>>,
    Json(request): Json<OprfRequest>,
) -> Result<Json<OprfResponse>, ApiError> {
    tracing::info!("received new OPRF request: {request:?}");

    Ok(Json(OprfResponse {
        job_id: request.job_id,
        response: format!("response to {}", request.request),
    }))
}

pub(crate) fn router(input_max_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/jobs", post(oprf_request))
        .layer(DefaultBodyLimit::max(input_max_body_limit))
}
