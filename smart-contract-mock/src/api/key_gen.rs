use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use oprf_types::{
    RpId,
    crypto::{RpSecretGenCiphertext, RpSecretGenCiphertexts, RpSecretGenCommitment},
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    services::rp_key_gen::{RpKeyGenService, RpKeyGenServiceError},
};
use oprf_core::ark_serde_compat;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyGenRound1Request {
    rp_id: RpId,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    sender: ark_babyjubjub::EdwardsAffine,
    contribution: RpSecretGenCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyGenRound2Request {
    rp_id: RpId,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    sender: ark_babyjubjub::EdwardsAffine,
    contribution: RpSecretGenCiphertexts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyGenReadRound2ContributionRequest {
    rp_id: RpId,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    sender: ark_babyjubjub::EdwardsAffine,
}

impl IntoResponse for RpKeyGenServiceError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            RpKeyGenServiceError::UnknownRp(rp_id) => {
                (StatusCode::NOT_FOUND, format!("cannot find {rp_id}")).into_response()
            }
            RpKeyGenServiceError::InRound1 => {
                (StatusCode::BAD_REQUEST, "already in round2").into_response()
            }
            RpKeyGenServiceError::InRound2 => {
                (StatusCode::BAD_REQUEST, "still in round1").into_response()
            }
            RpKeyGenServiceError::AlreadySubmitted => (
                StatusCode::BAD_REQUEST,
                "you already submitted for this round",
            )
                .into_response(),
        }
    }
}

async fn round1(
    State(key_gen_service): State<RpKeyGenService>,
    Form(req): Form<KeyGenRound1Request>,
) -> Result<(), RpKeyGenServiceError> {
    let KeyGenRound1Request {
        rp_id,
        sender,
        contribution,
    } = req;
    key_gen_service.add_round1_contribution(rp_id, sender, contribution)?;
    Ok(())
}

async fn read_round1_contributions(
    State(key_gen_service): State<RpKeyGenService>,
    Path(rp_id): Path<RpId>,
) -> Result<Json<Vec<RpSecretGenCommitment>>, RpKeyGenServiceError> {
    Ok(Json(key_gen_service.read_round1_contributions(rp_id)?))
}

async fn round2(
    State(key_gen_service): State<RpKeyGenService>,
    Form(req): Form<KeyGenRound2Request>,
) -> Result<(), RpKeyGenServiceError> {
    let KeyGenRound2Request {
        rp_id,
        sender,
        contribution,
    } = req;
    key_gen_service.add_round2_contribution(rp_id, sender, contribution)?;
    Ok(())
}

async fn read_round2_contributions(
    State(key_gen_service): State<RpKeyGenService>,
    Query(req): Query<KeyGenReadRound2ContributionRequest>,
) -> Result<Json<Vec<RpSecretGenCiphertext>>, RpKeyGenServiceError> {
    let KeyGenReadRound2ContributionRequest { rp_id, sender } = req;
    Ok(Json(
        key_gen_service.read_round2_contributions(rp_id, sender)?,
    ))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/round1", post(round1))
        .route("/round1/{}", get(read_round1_contributions))
        .route("/round2", post(round2))
        .route("/round2/read", get(read_round2_contributions))
}
