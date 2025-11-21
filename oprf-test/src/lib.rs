use std::{
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Duration,
};

use alloy::primitives::{Address, address};
use reqwest::StatusCode;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt as _,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner as _,
};
use testcontainers_modules::{anvil::AnvilNode, postgres::Postgres};

pub use oprf_service::rp_registry::{RpRegistry, Types::EcDsaPubkeyCompressed};

use crate::test_secret_manager::TestSecretManager;

pub mod credentials;
pub mod health_checks;
pub mod rp_registry_scripts;
pub mod test_secret_manager;
pub mod world_id_protocol_mock;

/// anvil wallet 0
pub const TACEO_ADMIN_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// anvil wallet 0
pub const TACEO_ADMIN_ADDRESS: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// anvil wallet 7
pub const OPRF_PEER_ADDRESS_0: Address = address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955");
/// anvil wallet 8
pub const OPRF_PEER_ADDRESS_1: Address = address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f");
/// anvil wallet 9
pub const OPRF_PEER_ADDRESS_2: Address = address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720");

// FIXME
// once we don't need to sign nonces ourself, remove this even in tests
// this signing key is constant and used by all rps so that we do not need to run init_key_gen every time
// and can instead reuse the key_material in the contract/secret_manager
//
// THIS IS NOT INTENDED FOR REAL USE IN PROD
pub static MOCK_RP_SECRET_KEY: LazyLock<k256::SecretKey> =
    LazyLock::new(|| k256::SecretKey::from_slice(&[42u8; 24]).unwrap());

async fn start_world_service(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    account_registry_contract: Address,
) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = oprf_service_world::config::OprfPeerConfig {
        environment: oprf_service_world::config::Environment::Dev,
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        request_lifetime: Duration::from_secs(5 * 60),
        session_cleanup_interval: Duration::from_micros(1000000),
        max_wait_time_shutdown: Duration::from_secs(10),
        user_verification_key_path: dir.join("../circom/main/query/OPRFQuery.vk.json"),
        rp_secret_id_prefix: format!("oprf/rp/n{id}"),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        rp_registry_contract,
        account_registry_contract,
        chain_ws_rpc_url: chain_ws_rpc_url.into(),
        key_gen_witness_graph_path: dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin"),
        key_gen_zkey_path: dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey"),
        wallet_private_key_secret_id: "wallet/privatekey".to_string(),
    };
    let never = async { futures::future::pending::<()>().await };

    tokio::spawn(async move {
        let res = oprf_service_world::start(config, Arc::new(secret_manager), never).await;
        eprintln!("service failed to start: {res:?}");
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    url
}

async fn start_example_service(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = oprf_service_example::config::OprfPeerConfig {
        environment: oprf_service_example::config::Environment::Dev,
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        request_lifetime: Duration::from_secs(5 * 60),
        session_cleanup_interval: Duration::from_micros(1000000),
        max_wait_time_shutdown: Duration::from_secs(10),
        rp_secret_id_prefix: format!("oprf/rp/n{id}"),
        rp_registry_contract,
        chain_ws_rpc_url: chain_ws_rpc_url.into(),
        key_gen_witness_graph_path: dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin"),
        key_gen_zkey_path: dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey"),
        wallet_private_key_secret_id: "wallet/privatekey".to_string(),
    };
    let never = async { futures::future::pending::<()>().await };

    tokio::spawn(async move {
        let res = oprf_service_example::start(config, Arc::new(secret_manager), never).await;
        eprintln!("service failed to start: {res:?}");
    });
    // very graceful timeout for CI
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub fn create_secret_managers() -> [TestSecretManager; 3] {
    [
        TestSecretManager::new(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        ),
        TestSecretManager::new(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        ),
        TestSecretManager::new(
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        ),
    ]
}

pub async fn start_world_services(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
    account_registry_contract: Address,
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    [
        start_world_service(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        start_world_service(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        start_world_service(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            account_registry_contract,
        )
        .await,
    ]
}

pub async fn start_example_services(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    [
        start_example_service(0, chain_ws_rpc_url, secret_manager0, key_gen_contract).await,
        start_example_service(1, chain_ws_rpc_url, secret_manager1, key_gen_contract).await,
        start_example_service(2, chain_ws_rpc_url, secret_manager2, key_gen_contract).await,
    ]
}

pub async fn postgres_testcontainer() -> eyre::Result<(ContainerAsync<Postgres>, String)> {
    let container = Postgres::default().with_network("network").start().await?;
    let ip = container.get_bridge_ip_address().await?;
    let db_url = format!("postgres://postgres:postgres@{ip}:5432/postgres");
    Ok((container, db_url))
}

pub async fn indexer_testcontainer(
    rpc_url: &str,
    ws_url: &str,
    registry_address: &str,
    db_url: &str,
) -> eyre::Result<(ContainerAsync<GenericImage>, String)> {
    let image = GenericImage::new(
        "ghcr.io/worldcoin/world-id-protocol/world-id-indexer",
        "sha-9cdaf09",
    )
    .with_exposed_port(8080.tcp())
    .with_wait_for(WaitFor::http(
        HttpWaitStrategy::new("/health")
            .with_port(8080.tcp())
            .with_response_matcher(|res| res.status() == StatusCode::OK),
    ))
    .with_network("network")
    .with_env_var("RPC_URL", rpc_url)
    .with_env_var("WS_URL", ws_url)
    .with_env_var("REGISTRY_ADDRESS", registry_address)
    .with_env_var("DATABASE_URL", db_url);
    // .with_exposed_host_port(anvil_port);

    let indexer_container = image.start().await.expect("can start indexer image");
    let indexer_url = format!(
        "http://localhost:{port}",
        port = indexer_container
            .get_host_port_ipv4(8080)
            .await
            .expect("can bind ip"),
    );
    Ok((indexer_container, indexer_url))
}

pub async fn anvil_testcontainer()
-> eyre::Result<(ContainerAsync<AnvilNode>, String, String, String, String)> {
    let container = AnvilNode::default().with_network("network").start().await?;
    let host_ip = container.get_host().await?;
    let host_port = container.get_host_port_ipv4(8545).await?;
    let bridge_ip = container.get_bridge_ip_address().await?;
    let host_rpc_url = format!("http://{host_ip}:{host_port}");
    let host_ws_url = format!("ws://{host_ip}:{host_port}");
    let bridge_rpc_url = format!("http://{bridge_ip}:8545");
    let bridge_ws_url = format!("ws://{bridge_ip}:8545");
    Ok((
        container,
        host_rpc_url,
        host_ws_url,
        bridge_rpc_url,
        bridge_ws_url,
    ))
}
