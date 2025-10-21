use alloy::primitives::Address;
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing::get};
use clap::Parser;
use oprf_test::world_id_protocol_mock::AuthTreeIndexer;
use std::{net::SocketAddr, sync::Arc};

#[derive(Parser, Debug)]
pub struct AuthTreeIndexerConfig {
    /// The bind addr of the AXUM server
    #[clap(
        long,
        env = "AUTH_TREE_INDEXER_BIND_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    pub bind_addr: SocketAddr,

    /// Chain URL.
    #[clap(
        long,
        env = "AUTH_TREE_INDEXER_WS_RPC_URL",
        default_value = "ws://127.0.0.1:8545"
    )]
    pub ws_rpc_url: String,

    /// The address of the AccountRegistry smart contract
    #[clap(
        long,
        env = "AUTH_TREE_INDEXER_CONTRACT_ADDRESS",
        default_value = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    )]
    contract_address: Address,
}

async fn get_proof(
    Path(account_id): Path<u64>,
    indexer: Arc<AuthTreeIndexer>,
) -> impl IntoResponse {
    match indexer.get_proof(account_id).await {
        Ok(proof_response) => (StatusCode::OK, Json(proof_response)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("info");
    let config = AuthTreeIndexerConfig::parse();

    tracing::info!("init AuthTreeIndexer...");
    let indexer =
        Arc::new(AuthTreeIndexer::init(config.contract_address, &config.ws_rpc_url).await?);

    tracing::info!("starting axum server...");
    let app = Router::new().route(
        "/proof/{account_id}",
        get({
            let indexer = Arc::clone(&indexer);
            move |path| get_proof(path, indexer)
        }),
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;

    tracing::info!("exiting...");

    Ok(())
}
