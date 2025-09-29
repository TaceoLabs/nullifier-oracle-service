use std::{path::PathBuf, time::Duration};

use oprf_client::BaseField;
use oprf_service::config::{Environment, OprfPeerConfig};
use oprf_types::{
    MerkleEpoch, RpId,
    crypto::RpNullifierKey,
    sc_mock::{
        AddPublicKeyRequest, AddPublicKeyResponse, MerklePath, SignNonceRequest, SignNonceResponse,
        UserPublicKey,
    },
};
use smart_contract_mock::config::SmartContractMockConfig;

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
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        max_merkle_depth: 30,
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

pub async fn register_rp(chain_url: &str) -> eyre::Result<(RpId, RpNullifierKey)> {
    let client = reqwest::Client::new();
    let rp_id = client
        .post(format!("{chain_url}/api/admin/register-new-rp"))
        .send()
        .await?
        .json::<RpId>()
        .await?;
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let res = client
                .get(format!("{chain_url}/api/rp/{}", rp_id.into_inner()))
                .send()
                .await
                .expect("smart contract is online");
            if res.status().is_success() {
                break res.json::<RpNullifierKey>().await.expect("can deserialize");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("can fetch");
    Ok((rp_id, rp_nullifier_key))
}

pub async fn register_public_key(
    chain_url: &str,
    public_key: UserPublicKey,
) -> eyre::Result<(MerkleEpoch, MerklePath)> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{chain_url}/api/admin/register-new-public-key"))
        .json(&AddPublicKeyRequest { public_key })
        .send()
        .await
        .expect("smart contract is online");
    if res.status().is_success() {
        let res = res
            .json::<AddPublicKeyResponse>()
            .await
            .expect("can get merkle path");
        Ok((res.epoch, res.path))
    } else {
        eyre::bail!("returned error: {:?}", res.text().await?);
    }
}

pub async fn sign_nonce(
    chain_url: &str,
    rp_id: RpId,
    nonce: BaseField,
) -> eyre::Result<SignNonceResponse> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{chain_url}/api/rp/sign"))
        .json(&SignNonceRequest { rp_id, nonce })
        .send()
        .await
        .expect("smart contract is online");
    if res.status().is_success() {
        let res = res
            .json::<SignNonceResponse>()
            .await
            .expect("can get merkle path");
        Ok(res)
    } else {
        eyre::bail!("returned error: {:?}", res.text().await?);
    }
}
