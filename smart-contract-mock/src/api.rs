use axum::Router;

use crate::AppState;

mod admin;
mod oprf;

pub(crate) fn build() -> Router<AppState> {
    Router::new().nest("oprf/", oprf::router())
}
