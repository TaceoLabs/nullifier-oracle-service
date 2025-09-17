use axum::Router;

use crate::AppState;

mod admin;
pub(crate) mod errors;
mod key_gen;
mod public_key_registry;
mod rp_registry;

pub(crate) fn build() -> Router<AppState> {
    Router::new()
        .nest("/merkle", public_key_registry::router())
        .nest("/rp/keygen", key_gen::router())
        .nest("/rp", rp_registry::router())
        .nest("/admin", admin::router())
}
