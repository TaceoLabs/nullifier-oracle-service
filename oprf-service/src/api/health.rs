use axum::{
    Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::AppState;

use super::errors::ApiError;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/live", get(live))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

async fn health(State(_app_state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok((StatusCode::OK, "healthy"))
}

async fn ready(State(_register): State<AppState>) -> impl IntoResponse {
    // TODO: detect from register if service is ready?
    (StatusCode::OK, "ready")
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, "live")
}
