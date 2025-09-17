use axum::{Json, Router, extract::State, routing::post};
use oprf_types::chain::{
    SecretGenFinalizeContribution, SecretGenRound1Contribution, SecretGenRound2Contribution,
};
use tracing::instrument;

use crate::{AppState, api::errors::ApiResult, services::rp_key_gen::RpNullifierGenService};

#[instrument(level = "info", skip_all, fields(rp_id=%req.rp_id, sender=%req.sender))]
async fn round1(
    State(key_gen_service): State<RpNullifierGenService>,
    Json(req): Json<SecretGenRound1Contribution>,
) -> ApiResult<()> {
    let SecretGenRound1Contribution {
        rp_id,
        sender,
        contribution,
    } = req;
    tracing::info!("got contribution from {sender}");
    key_gen_service.add_round1_contribution(rp_id, sender, contribution)?;
    Ok(())
}

async fn round2(
    State(key_gen_service): State<RpNullifierGenService>,
    Json(req): Json<SecretGenRound2Contribution>,
) -> ApiResult<()> {
    let SecretGenRound2Contribution {
        rp_id,
        sender,
        contribution,
    } = req;
    key_gen_service.add_round2_contribution(rp_id, sender, contribution)?;
    Ok(())
}

async fn finalize(
    State(key_gen_service): State<RpNullifierGenService>,
    Json(req): Json<SecretGenFinalizeContribution>,
) -> ApiResult<()> {
    let SecretGenFinalizeContribution { rp_id, sender } = req;
    key_gen_service.oprf_finalize(rp_id, sender)?;
    Ok(())
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/round1", post(round1))
        .route("/round2", post(round2))
        .route("/finalize", post(finalize))
}
