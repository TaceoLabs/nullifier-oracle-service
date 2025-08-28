use std::sync::Arc;

use axum::{
    Json,
    extract::{DefaultBodyLimit, State},
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{AppState, api::errors::ApiError, config::ServiceConfig};

const OPRF_TAG: &str = "oprf";

#[derive(Debug, Deserialize, ToSchema)]
pub struct OprfRequest {
    pub job_id: Uuid,
    // TODO
    pub request: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OprfResponse {
    pub job_id: Uuid,
    // TODO
    pub response: String,
}

#[utoipa::path(
        post,
        path = "/request",
        tag = OPRF_TAG,
        request_body(content = inline(OprfRequest), content_type = "application/json"),
        responses(
            (status = 200, description = "Schedule a new job", body=OprfResponse),
            (status = "5XX", description = "Internal Server Error", body=ApiError),
        ),
    )]
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

pub(crate) fn router(input_max_body_limit: usize) -> OpenApiRouter<AppState> {
    OpenApiRouter::new().nest(
        "/jobs",
        OpenApiRouter::new()
            .routes(routes!(oprf_request))
            .layer(DefaultBodyLimit::max(input_max_body_limit)),
    )
}
