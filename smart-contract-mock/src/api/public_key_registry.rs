use axum::{
    Json, Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use eyre::Context;
use oprf_types::sc_mock::{FetchRootsRequest, IsValidEpochRequest, MerkleRootUpdate};
use tokio::sync::broadcast;
use tracing::instrument;

use crate::{AppState, services::merkle_registry::MerkleRootRegistry};

/// Subscribe logic.
///
/// Listens to the bus and forwards the `MerkleRoot` to the websocket. If the client closes the stream, we will realize only when we write to the websocket again. As we will add new public keys regularly we expect that this is not a problem for resource exhaustion, even though we would want to handle this appropriately in a real implementation.
async fn handle_subscribe(
    mut ws: WebSocket,
    mut bus: broadcast::Receiver<MerkleRootUpdate>,
) -> eyre::Result<()> {
    loop {
        let merkle_root = bus.recv().await.context("lagging or sender closed")?;
        ws.send(Message::text(
            serde_json::to_string(&merkle_root).expect("can serialize"),
        ))
        .await
        .context("client closed stream")?;
    }
}

/// Allows the OPRF-Service to subscribe to updates of the [`MerkleRootRegistry`].
///
/// This method will send the new merkle root every time a new `PublicKey` is added.
/// Implementation: This is some quick-and-dirty implementation for the websocket. It does not allow to client close the connection gracefully only by shutting down the Ws (without sending Close frames). Maybe if we find the time we can fix this but priority for that was not too high as this is a mock impl anyways.
async fn subscribe_merkle_updates(
    ws: WebSocketUpgrade,
    State(bus): State<broadcast::Receiver<MerkleRootUpdate>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(|error| tracing::warn!("cannot upgrade ws connection: {error:?}"))
        .on_upgrade(|ws| async move {
            tracing::debug!("got merkle root subscribe request");
            if let Err(err) = handle_subscribe(ws, bus).await {
                tracing::debug!("closed websocket: {err:?}");
            }
        })
}

/// Fetches a defined amount roots that are currently valid.
///
/// If the given amount is larger than the currently cached roots, this method should return all roots that are currently cached.
/// This method should only be called once from the OPRF-Service during startup.
#[instrument(level = "debug", skip(merkle_registry))]
async fn fetch_roots(
    State(merkle_registry): State<MerkleRootRegistry>,
    Query(req): Query<FetchRootsRequest>,
) -> Json<Vec<MerkleRootUpdate>> {
    tracing::debug!("fetch request for {} roots", req.amount);
    Json(merkle_registry.fetch_roots(req.amount))
}

/// Route that allows the OPRF-Service to check whether a given root is actually a valid merkle root.
///
/// The server will hold a defined amount of old hashes as-well and will verify that is belonged to some latest amount of hashes. If the merkle root is too old, this will return NOT_FOUND. The method will also return NOT_FOUND if the provided hash is not valid.
#[instrument(level = "debug", skip(merkle_registry))]
async fn is_valid_root(
    State(merkle_registry): State<MerkleRootRegistry>,
    Query(IsValidEpochRequest { epoch }): Query<IsValidEpochRequest>,
) -> impl IntoResponse {
    if let Some(root) = merkle_registry.get_by_epoch(epoch) {
        tracing::debug!("{epoch} is a valid epoch");
        (StatusCode::OK, root.to_string()).into_response()
    } else {
        tracing::debug!("{epoch} is NOT a valid epoch");
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Builds the router for the OPRF-Service.
///
/// This is the logic that acts as the Smart Contract (SC) Mock for the OPRF-Service. This is heavy subject-to-change when we get more information how the interface to the SC looks in the future.
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/subscribe", get(subscribe_merkle_updates))
        .route("/valid", get(is_valid_root))
        .route("/fetch", get(fetch_roots))
}
