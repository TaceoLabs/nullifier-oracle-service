use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub(crate) mod oprf;

use crate::{AppState, api};

/// Builds the unauthenticated routes. At the moment all requests are unauthenticated.
fn unauthenticated_routes(input_max_body_limit: usize) -> Router<AppState> {
    oprf::router(input_max_body_limit)
}

// Builds the axum router for v1. Limits the max body limit to provided value.
pub(crate) fn build(input_max_body_limit: usize) -> Router<AppState> {
    let merged = Router::new().merge(unauthenticated_routes(input_max_body_limit));

    // Setup a restrictive CORS layer for the v1 api. We only want to consume json, therefore
    // we allow the content-type header (and user-agent header). As we only have POST request,
    // we prohibit all other, expect for OPTION preflight.
    //
    // We setup a wildcard as we are a public API and everyone can access the service.
    let cors = CorsLayer::new()
        .allow_credentials(false)
        .allow_headers([http::header::CONTENT_TYPE, http::header::USER_AGENT])
        .allow_methods([http::Method::POST, http::Method::OPTIONS])
        .allow_origin(AllowOrigin::any());
    Router::new()
        .nest("/oprf", merged)
        .merge(api::health::routes())
        .layer(cors)
}
