use axum::{Json, Router, extract::State, routing::post};
use oprf_types::{
    RpId,
    sc_mock::{AddPublicKeyRequest, AddPublicKeyResponse},
};

use crate::{
    AppState,
    services::{merkle_registry::MerkleRootRegistry, rp_key_gen::RpNullifierGenService},
};

async fn register_new_rp(State(rp_key_gen): State<RpNullifierGenService>) -> Json<RpId> {
    Json(rp_key_gen.register())
}

async fn register_new_public_key(
    State(merkle_registry): State<MerkleRootRegistry>,
    Json(req): Json<AddPublicKeyRequest>,
) -> Json<AddPublicKeyResponse> {
    let mut rng = rand::thread_rng();
    let (epoch, path) = merkle_registry.add_public_key(req.public_key, &mut rng);
    Json(AddPublicKeyResponse { epoch, path })
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/register-new-rp", post(register_new_rp))
        .route("/register-new-public-key", post(register_new_public_key))
}
