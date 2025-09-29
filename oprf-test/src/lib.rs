use std::{path::PathBuf, time::Duration};

use oprf_service::config::{Environment, OprfPeerConfig};

pub mod oprf;
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
        chain_url: "http://localhost:6789".to_string(),
        chain_check_interval: Duration::from_millis(1000),
        chain_epoch_max_difference: 10,
        private_key_secret_id: format!("oprf/sk/n{id}"),
        dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
        max_merkle_store_size: 10,
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

pub async fn start_services() -> [String; 3] {
    [
        start_service(0).await,
        start_service(1).await,
        start_service(2).await,
    ]
}
