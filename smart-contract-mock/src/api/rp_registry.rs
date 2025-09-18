use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use oprf_core::ark_serde_compat;
use oprf_types::{KeyEpoch, RpId};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    services::{rp_key_gen::RpKeyGenService, rp_registry::RpRegistry},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadPkResponse {
    epoch: KeyEpoch,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    key: ark_babyjubjub::EdwardsAffine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadEventsRequest {
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    key: ark_babyjubjub::EdwardsAffine,
}

async fn read_pk(State(registry): State<RpRegistry>, Path(rp_id): Path<RpId>) -> impl IntoResponse {
    match registry.get_public_key(rp_id) {
        Some(key) => Json(ReadPkResponse {
            epoch: KeyEpoch::default(),
            key,
        })
        .into_response(),
        None => (StatusCode::NOT_FOUND, format!("unknown rp_id: {rp_id}")).into_response(),
    }
}

async fn read_events(
    State(key_gen_service): State<RpKeyGenService>,
    Query(req): Query<ReadEventsRequest>,
) {
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/{}", get(read_pk))
        .route("/event", get(read_pk))
}
