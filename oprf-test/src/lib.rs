use std::{path::PathBuf, sync::LazyLock, time::Duration};

use alloy::primitives::{Address, address};
use oprf_service::config::{Environment, OprfPeerConfig};

pub mod credentials;
pub mod rp_registry_scripts;
pub mod test_setup_utils;
pub mod world_id_protocol_mock;

/// anvil wallet 0
pub const TACEO_ADMIN_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// anvil wallet 0
pub const TACEO_ADMIN_ADDRESS: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// anvil wallet 7
pub const OPRF_PEER_ADDRESS_0: Address = address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955");
pub const OPRF_PEER_PRIVATE_KEY_0: &str =
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";
/// anvil wallet 8
pub const OPRF_PEER_ADDRESS_1: Address = address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f");
pub const OPRF_PEER_PRIVATE_KEY_1: &str =
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
/// anvil wallet 9
pub const OPRF_PEER_ADDRESS_2: Address = address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720");
pub const OPRF_PEER_PRIVATE_KEY_2: &str =
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

// FIXME
// once we dont need to sign nonces ourself, remove this even in tests
// this signing key is constant and used by all rps so that we do not need to run init_key_gen every time
// and can instead reuse the key_material in the contract/secret_manager
//
// THIS IS NOT INTENDED FOR REAL USE IN PROD
pub static MOCK_RP_SECRET_KEY: LazyLock<k256::SecretKey> =
    LazyLock::new(|| k256::SecretKey::from_slice(&[42u8; 24]).unwrap());

async fn start_service(
    id: usize,
    chain_ws_rpc_url: &str,
    wallet_private_key: &str,
    private_key: ark_babyjubjub::Fr,
    rp_registry_contract: Address,
    account_registry_contract: Address,
) -> String {
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
        user_verification_key_path: dir.join("../circom/query.vk.json"),
        private_key: private_key.to_string().into(),
        max_merkle_store_size: 10,
        current_time_stamp_max_difference: Duration::from_secs(10),
        signature_history_cleanup_interval: Duration::from_secs(30),
        rp_registry_contract,
        account_registry_contract,
        wallet_private_key: wallet_private_key.into(),
        chain_ws_rpc_url: chain_ws_rpc_url.to_string(),
        key_gen_witness_graph_path: dir.join("../circom/keygen_graph.bin"),
        key_gen_zkey_path: dir.join("../circom/keygen_13.zkey"),
        key_gen_from_block: 0,
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

pub async fn start_services(
    chain_ws_rpc_url: &str,
    peer_private_keys: Vec<ark_babyjubjub::Fr>,
    key_gen_contract: Address,
    account_registry_contract: Address,
) -> [String; 3] {
    [
        start_service(
            0,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_0,
            peer_private_keys[0],
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        start_service(
            1,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_1,
            peer_private_keys[1],
            key_gen_contract,
            account_registry_contract,
        )
        .await,
        start_service(
            2,
            chain_ws_rpc_url,
            OPRF_PEER_PRIVATE_KEY_2,
            peer_private_keys[2],
            key_gen_contract,
            account_registry_contract,
        )
        .await,
    ]
}
