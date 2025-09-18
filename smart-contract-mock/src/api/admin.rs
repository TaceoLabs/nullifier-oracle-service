use axum::{Json, Router, extract::State, routing::post};
use oprf_types::RpId;

use crate::{AppState, services::rp_key_gen::RpKeyGenService};

async fn register_new_rp(State(rp_key_gen): State<RpKeyGenService>) -> Json<RpId> {
    Json(rp_key_gen.register())
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/", post(register_new_rp))
}
