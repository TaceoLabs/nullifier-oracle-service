use crate::test_secret_manager::TestSecretManager;
use alloy::{
    primitives::{Address, address},
    providers::DynProvider,
};
use eyre::Context as _;
use oprf_types::{
    OprfKeyId, ShareEpoch, chain::OprfKeyRegistry::OprfKeyRegistryInstance, crypto::OprfPublicKey,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub mod health_checks;
pub mod oprf_key_registry_scripts;
pub mod test_secret_manager;

/// anvil wallet 0
pub const TACEO_ADMIN_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const TACEO_ADMIN_ADDRESS: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// anvil wallet 7
pub const OPRF_PEER_PRIVATE_KEY_0: &str =
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";
pub const OPRF_PEER_ADDRESS_0: Address = address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955");
/// anvil wallet 8
pub const OPRF_PEER_PRIVATE_KEY_1: &str =
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
pub const OPRF_PEER_ADDRESS_1: Address = address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f");
/// anvil wallet 9
pub const OPRF_PEER_PRIVATE_KEY_2: &str =
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
pub const OPRF_PEER_ADDRESS_2: Address = address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720");

async fn start_node(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
    wallet_address: Address,
) -> String {
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = oprf_service_example::config::ExampleOprfNodeConfig {
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        max_wait_time_shutdown: Duration::from_secs(10),
        service_config: oprf_service::config::OprfNodeConfig {
            environment: oprf_service::config::Environment::Dev,
            rp_secret_id_prefix: format!("oprf/rp/n{id}"),
            oprf_key_registry_contract: rp_registry_contract,
            chain_ws_rpc_url: chain_ws_rpc_url.into(),
            ws_max_message_size: 512 * 1024,
            session_lifetime: Duration::from_secs(60),
            wallet_address,
            get_oprf_key_material_timeout: Duration::from_secs(60),
        },
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

async fn start_key_gen(
    id: usize,
    chain_ws_rpc_url: &str,
    secret_manager: TestSecretManager,
    rp_registry_contract: Address,
) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = oprf_key_gen::config::OprfKeyGenConfig {
        environment: oprf_key_gen::config::Environment::Dev,
        oprf_key_registry_contract: rp_registry_contract,
        chain_ws_rpc_url: chain_ws_rpc_url.into(),
        rp_secret_id_prefix: format!("oprf/rp/n{id}"),
        wallet_private_key_secret_id: "wallet/privatekey".to_string(),
        key_gen_zkey_path: dir.join("../circom/main/key-gen/OPRFKeyGen.13.arks.zkey"),
        key_gen_witness_graph_path: dir.join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin"),
        max_wait_time_shutdown: Duration::from_secs(10),
        max_epoch_cache_size: 3,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = oprf_key_gen::start(config, Arc::new(secret_manager), never).await;
        eprintln!("key-gen failed to start: {res:?}");
    });
}

pub fn create_secret_managers() -> [TestSecretManager; 3] {
    [
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_0),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_1),
        TestSecretManager::new(OPRF_PEER_PRIVATE_KEY_2),
    ]
}

pub async fn start_nodes(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) -> [String; 3] {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    tokio::join!(
        start_node(
            0,
            chain_ws_rpc_url,
            secret_manager0,
            key_gen_contract,
            OPRF_PEER_ADDRESS_0,
        ),
        start_node(
            1,
            chain_ws_rpc_url,
            secret_manager1,
            key_gen_contract,
            OPRF_PEER_ADDRESS_1,
        ),
        start_node(
            2,
            chain_ws_rpc_url,
            secret_manager2,
            key_gen_contract,
            OPRF_PEER_ADDRESS_2,
        )
    )
    .into()
}

pub async fn start_key_gens(
    chain_ws_rpc_url: &str,
    secret_manager: [TestSecretManager; 3],
    key_gen_contract: Address,
) {
    let [secret_manager0, secret_manager1, secret_manager2] = secret_manager;
    tokio::join!(
        start_key_gen(0, chain_ws_rpc_url, secret_manager0, key_gen_contract),
        start_key_gen(1, chain_ws_rpc_url, secret_manager1, key_gen_contract),
        start_key_gen(2, chain_ws_rpc_url, secret_manager2, key_gen_contract),
    );
}

// pub async fn fetch_oprf_public_key_by_epoch(
//     oprf_key_id: OprfKeyId,
//     epoch: ShareEpoch,
//     contract: &OprfKeyRegistryInstance<DynProvider>,
//     max_wait_time: Duration,
// ) -> eyre::Result<OprfPublicKey> {
//     tracing::info!("fetching OPRF public-key for epoch {epoch}..");
//     let mut interval = tokio::time::interval(Duration::from_millis(500));
//     let oprf_public_key = tokio::time::timeout(max_wait_time, async move {
//         loop {
//             interval.tick().await;
//             let maybe_oprf_public_key = contract
//                 .getOprfPublicKeyAndEpoch(oprf_key_id.into_inner())
//                 .call()
//                 .await;
//             if let Ok(oprf_public_key) = maybe_oprf_public_key
//                 && oprf_public_key.epoch == epoch.into_inner()
//             {
//                 return eyre::Ok(OprfPublicKey::new(oprf_public_key.key.try_into()?));
//             }
//         }
//     })
//     .await
//     .context("could not fetch rp nullifier key in time")?
//     .context("while polling RP key")?;
//     Ok(oprf_public_key)
// }
