use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use oprf_types::{RpId, chain::ChainEvent, crypto::RpNullifierKey, sc_mock::ReadEventsRequest};
use tracing::instrument;

use crate::{
    AppState,
    api::errors::{ApiErrors, ApiResult},
    services::{rp_key_gen::RpNullifierGenService, rp_registry::RpRegistry},
};

async fn read_pk(
    State(registry): State<RpRegistry>,
    Path(rp_id): Path<RpId>,
) -> ApiResult<Json<RpNullifierKey>> {
    let key = registry
        .get_public_key(rp_id)
        .ok_or_else(|| ApiErrors::NotFound(format!("unknown rp_id: {rp_id}")))?;
    Ok(Json(key))
}

#[instrument(level = "debug", skip_all)]
async fn read_events(
    State(key_gen_service): State<RpNullifierGenService>,
    Query(ReadEventsRequest { party_id }): Query<ReadEventsRequest>,
) -> ApiResult<Json<Vec<ChainEvent>>> {
    tracing::debug!("ReadEvent from: {party_id}");
    Ok(Json(key_gen_service.read_events(party_id)?))
}

#[instrument(level = "debug", skip_all)]
async fn list_rps(State(rp_registry): State<RpRegistry>) -> ApiResult<Json<Vec<RpId>>> {
    Ok(Json(rp_registry.list_public_keys()))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/{rp_id}", get(read_pk))
        .route("/list", get(list_rps))
        .route("/event", get(read_events))
}
