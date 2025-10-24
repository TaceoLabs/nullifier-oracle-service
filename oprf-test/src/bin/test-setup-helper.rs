use clap::Parser;
use oprf_test::test_setup_utils;

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
    #[clap(long, env = "CHAIN_WS_RPC_URL")]
    pub chain_ws_rpc_url: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("test_setup_helper=debug");
    let config = InitRpRegistryConfig::parse();
    let InitRpRegistryConfig {
        private_key_secret_id_prefix,
        overwrite_old_keys,
        chain_ws_rpc_url,
    } = config;

    let peer_public_keys =
        test_setup_utils::generate_keys(3, &private_key_secret_id_prefix, overwrite_old_keys)
            .await?;

    if let Some(chain_ws_rpc_url) = chain_ws_rpc_url {
        tracing::info!("deploying rp-registry-test-setup at {chain_ws_rpc_url}");
        let rp_registry =
            test_setup_utils::deploy_rp_registry(&chain_ws_rpc_url, peer_public_keys)?;
        tracing::info!("RpRegistry deployed to {rp_registry}");
    } else {
        tracing::info!("skipping rp-registry-deployment");
        tracing::info!("==== Public Keys ====");
        for public_key in peer_public_keys {
            tracing::info!("{public_key}");
        }
        tracing::info!("=====================");
    }

    Ok(())
}
