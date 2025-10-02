use std::{path::PathBuf, time::Duration};

use oprf_service::config::{Environment, OprfPeerConfig};
use smart_contract_mock::config::SmartContractMockConfig;

pub mod credentials;
pub mod key_gen_sc_mock;
pub mod sc_mock;

async fn start_service(id: usize) -> String {
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
        key_gen_rpc_url: "http://localhost:6789".to_string(),
        chain_epoch_max_difference: 10,
        private_key_secret_id: format!("oprf/sk/n{id}"),
        dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        max_merkle_depth: 30,
        key_gen_contract: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .expect("works"),
        chain_url: "ws://localhost:8545".to_string(),
        wallet_private_key: "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
            .into(),
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

pub async fn start_services() -> [String; 3] {
    [
        start_service(0).await,
        start_service(1).await,
        start_service(2).await,
    ]
}
