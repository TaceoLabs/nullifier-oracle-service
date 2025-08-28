use axum::{
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;

use super::errors::ApiError;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(ready))
        .routes(routes!(live))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

const HEALTH_TAG: &str = "Health";

#[utoipa::path(
        get,
        path = "/health",
        tag = HEALTH_TAG,
        responses(
            (status = 200, description = "The manager is healthy"),
            (status = "5XX", description = "Internal Server Error", body=ApiError),
        ),
    )]
async fn health(State(_app_state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok((StatusCode::OK, "healthy"))
}

#[utoipa::path(
        get,
        path = "/health/ready",
        tag = HEALTH_TAG,
        responses(
            (status = 200, description = "The manager is healthy"),
            (status = "5XX", description = "Internal Server Error", body=ApiError),
        ),
    )]
async fn ready(State(_register): State<AppState>) -> impl IntoResponse {
    // TODO: detect from register if service is ready?
    (StatusCode::OK, "ready")
}

#[utoipa::path(
        get,
        path = "/health/live",
        tag = HEALTH_TAG,
        responses(
            (status = 200, description = "The manager is healthy"),
            (status = "5XX", description = "Internal Server Error", body=ApiError),
        ),
    )]
async fn live() -> impl IntoResponse {
    (StatusCode::OK, "live")
}
