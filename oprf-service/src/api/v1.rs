use axum::Router;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

pub mod oprf;

use crate::{AppState, api};

#[derive(OpenApi)]
#[openapi(
        info(version = "1.0", title = "TACEO OPRF Service", license(name= "MIT", identifier = "MIT")),
        tags(
            (name = "oprf-service", description = "TACEO:OPRF - Oblivious Pseudorandom Function Service"),
        )
    )]
pub struct ApiDoc;

fn unauthenticated_routes(input_max_body_limit: usize) -> OpenApiRouter<AppState> {
    OpenApiRouter::new().merge(oprf::router(input_max_body_limit))
}

/// Build the v1 API with login routes located at "/". Panics if another
/// API registers login routes as well.
pub(crate) fn build(app_state: AppState) -> Router {
    let input_max_body_limit = app_state.config.input_max_body_limit;

    let merged = OpenApiRouter::new().merge(unauthenticated_routes(input_max_body_limit));

    let (router, apidoc) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api/v1", merged)
        .merge(api::health::routes())
        .split_for_parts();

    let swagger_ui =
        Router::new().merge(SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", apidoc));

    router.merge(swagger_ui).with_state(app_state)
}
