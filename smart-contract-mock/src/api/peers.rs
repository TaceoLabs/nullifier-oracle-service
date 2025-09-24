use axum::{Json, Router, extract::State, routing::post};
use oprf_types::sc_mock::{GetPartyIdRequest, GetPartyIdResponse};
use tracing::instrument;

use crate::{
    AppState,
    api::errors::{ApiErrors, ApiResult},
    services::peer_key_registry::OprfPeerKeyRegistry,
};

#[instrument(level = "debug", skip(peer_keys))]
async fn get_party_id(
    State(peer_keys): State<OprfPeerKeyRegistry>,
    Json(GetPartyIdRequest { key }): Json<GetPartyIdRequest>,
) -> ApiResult<Json<GetPartyIdResponse>> {
    match peer_keys.get_party_id(key) {
        Some(party_id) => {
            tracing::debug!("sending peer its id: {party_id}");
            Ok(Json(GetPartyIdResponse { party_id }))
        }
        None => Err(ApiErrors::NotFound(format!("cannot find peer: {key}"))),
    }
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/id", post(get_party_id))
}
