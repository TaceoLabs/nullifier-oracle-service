use std::path::PathBuf;

use clap::Parser;
use oprf_test::test_setup_utils;

#[derive(Parser, Debug)]
pub struct TestSetupHelperConfig {
    /// The dir to write the private keys to
    #[clap(long, env = "PRIVATE_KEYS_OUT_DIR")]
    pub private_keys_out_dir: PathBuf,

    /// The websocket rpc url of the chain
    #[clap(long, env = "CHAIN_WS_RPC_URL")]
    pub chain_ws_rpc_url: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("test_setup_helper=debug");
    let config = TestSetupHelperConfig::parse();
    let TestSetupHelperConfig {
        private_keys_out_dir,
        chain_ws_rpc_url,
    } = config;

    let (peer_public_keys, peer_private_keys) = test_setup_utils::generate_keys(3);

    for (i, private_key) in peer_private_keys.into_iter().enumerate() {
        std::fs::write(
            private_keys_out_dir.join(format!("oprf_peer_private_key_{i}")),
            private_key.to_string(),
        )?;
    }

    if let Some(chain_ws_rpc_url) = chain_ws_rpc_url {
        tracing::info!("deploying rp-registry-test-setup at {chain_ws_rpc_url}");
        test_setup_utils::deploy_rp_registry(&chain_ws_rpc_url, peer_public_keys)?;
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
