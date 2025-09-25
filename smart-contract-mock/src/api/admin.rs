use axum::{Json, Router, extract::State, routing::post};
use oprf_types::RpId;

use crate::{AppState, services::rp_key_gen::RpNullifierGenService};

async fn register_new_rp(State(rp_key_gen): State<RpNullifierGenService>) -> Json<RpId> {
    Json(rp_key_gen.register())
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/register-new-rp", post(register_new_rp))
}
