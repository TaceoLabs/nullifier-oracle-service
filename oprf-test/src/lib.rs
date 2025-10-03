use std::{path::PathBuf, time::Duration};

use oprf_service::config::{Environment, OprfPeerConfig};
use smart_contract_mock::config::SmartContractMockConfig;

pub mod credentials;
pub mod sc_mock;
pub mod world_id_protocol_mock;

async fn start_service(id: usize, chain_ws_rpc_url: &str) -> String {
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
        chain_url: "http://localhost:6789".to_string(),
        chain_check_interval: Duration::from_millis(1000),
        chain_epoch_max_difference: 10,
        private_key_secret_id: format!("oprf/sk/n{id}"),
        dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        max_merkle_depth: 30,
        chain_ws_rpc_url: chain_ws_rpc_url.to_string(),
        account_registry_contract_address: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0".to_string(),
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

pub async fn start_smart_contract_mock() -> String {
    let url = "http://localhost:6789".to_string();
    let config = SmartContractMockConfig {
        bind_addr: "0.0.0.0:6789".parse().expect("can parse"),
        max_root_cache_size: 10,
        add_pk_interval: Duration::from_secs(30),
        init_rp_registry: 1,
        add_rp_interval: Duration::from_secs(30),
        seed: 42,
        oprf_services: 3,
        oprf_degree: 1,
        oprf_public_keys_secret_id: "oprf/sc/pubs".to_string(),
        merkle_depth: 30,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = smart_contract_mock::start(config, never).await;
        eprintln!("smart contract mock failed to start: {res:?}");
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
        start_service(0, chain_ws_rpc_url).await,
        start_service(1, chain_ws_rpc_url).await,
        start_service(2, chain_ws_rpc_url).await,
    ]
}
