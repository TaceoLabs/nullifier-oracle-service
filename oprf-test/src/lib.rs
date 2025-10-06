use std::{path::PathBuf, time::Duration};

use oprf_service::config::{Environment, OprfPeerConfig};

use crate::{
    key_gen_sc_mock::DEFAULT_KEY_GEN_CONTRACT_ADDRESS,
    world_id_protocol_mock::DEFAULT_ACCOUNT_REGISTRY_ADDRESS,
};

pub mod credentials;
pub mod key_gen_sc_mock;
pub mod world_id_protocol_mock;

async fn start_service(id: usize, chain_ws_rpc_url: &str, wallet_private_key: &str) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = OprfPeerConfig {
        environment: Environment::Dev,
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        input_max_body_limit: 32768,
        request_lifetime: Duration::from_secs(5 * 60),
        session_cleanup_interval: Duration::from_micros(1000000),
        max_concurrent_jobs: 100000,
        max_wait_time_shutdown: Duration::from_secs(10),
        session_store_mailbox: 4096,
        user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
        chain_epoch_max_difference: 10,
        private_key_secret_id: format!("oprf/sk/n{id}"),
        dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        max_merkle_depth: 30,
        key_gen_contract: DEFAULT_KEY_GEN_CONTRACT_ADDRESS,
        account_registry_contract: DEFAULT_ACCOUNT_REGISTRY_ADDRESS,
        wallet_private_key: wallet_private_key.into(),
        chain_ws_rpc_url: chain_ws_rpc_url.to_string(),
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = oprf_service::start(config, never).await;
        eprintln!("service failed to start: {res:?}");
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn start_services(chain_ws_rpc_url: &str) -> [String; 3] {
    [
        start_service(
            0,
            chain_ws_rpc_url,
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        )
        .await,
        start_service(
            1,
            chain_ws_rpc_url,
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        )
        .await,
        start_service(
            2,
            chain_ws_rpc_url,
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        )
        .await,
    ]
}
