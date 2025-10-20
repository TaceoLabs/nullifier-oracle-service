use clap::Parser;
use oprf_test::init_rp_registry;

#[derive(Parser, Debug)]
pub struct InitRpRegistryConfig {
    /// The secret ID prefix
    ///
    /// The final secret ID will then be `secret_id0`|`PartyID`
    #[clap(long, env = "SECRET_ID_PREFIX", default_value = "oprf/sk")]
    pub private_key_secret_id_prefix: String,

    /// Whether old keys should be overwritten
    #[clap(long, env = "OVERWRITE", default_value = "false")]
    pub overwrite_old_keys: bool,

    /// The websocket rpc url of the chain
    #[clap(long, env = "CHAIN_WS_RPC_URL", default_value = "ws://127.0.0.1:8545")]
    pub chain_ws_rpc_url: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("init_rp_registry_contract=debug");
    let config = InitRpRegistryConfig::parse();
    let InitRpRegistryConfig {
        private_key_secret_id_prefix,
        overwrite_old_keys,
        chain_ws_rpc_url,
    } = config;

    init_rp_registry::start(
        &chain_ws_rpc_url,
        &private_key_secret_id_prefix,
        overwrite_old_keys,
    )
    .await?;
    Ok(())
}
