use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    signers::k256::{self, ecdsa::signature::Signer as _},
};
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use clap::Parser;
use eyre::Context as _;
use oprf_client::{
    MerkleMembership, NullifierArgs, OprfQuery, UserKeyMaterial, groth16::Groth16,
    zk::Groth16Material,
};
use oprf_service::rp_registry::{KeyGen, Types};
use oprf_test::world_id_protocol_mock::{self};
use oprf_test::{rp_registry_scripts, world_id_protocol_mock::InclusionProofResponse};
use oprf_types::{RpId, ShareEpoch, crypto::RpNullifierKey};
use parking_lot::Mutex;
use rand::SeedableRng;
use secrecy::{ExposeSecret, SecretString};
use tokio::task::JoinSet;

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF Services
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_SERVICES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000, http://127.0.0.1:10001, http://127.0.0.1:10002"
    )]
    pub services: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the KeyGen contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_KEY_GEN_CONTRACT",
        default_value = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
    )]
    pub key_gen_contract: Address,

    /// The Address of the KeyGen contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_ACCOUNT_REGISTRY_CONTRACT",
        default_value = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    )]
    pub account_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_WS_RPC_URL",
        default_value = "ws://localhost:8545"
    )]
    pub chain_ws_rpc_url: String,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF peers
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// The interval in which nullifiers are generated
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NULLIFIER_INTERVAL",
        default_value="1s",
        value_parser = humantime::parse_duration
    )]
    pub nullifier_interval: Duration,

    /// The amount of nullifiers to generate
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub nullifier_num: usize,

    /// The interval in which stats are logged
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_STATS_INTERVAL",
        default_value="5s",
        value_parser = humantime::parse_duration
    )]
    pub stats_interval: Duration,

    /// AuthTreeIndexer address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_AUTH_TREE_INDEXER_API_URL",
        default_value = "http://localhost:8080"
    )]
    pub auth_tree_indexer_api_url: String,

    /// AccountRegistry account id
    #[clap(long, env = "OPRF_DEV_CLIENT_ACCOUNT_ID", default_value = "1")]
    pub account_id: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_nullifier(
    services: &[String],
    threshold: usize,
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    nonce: ark_babyjubjub::Fq,
    current_time_stamp: u64,
    signature: k256::ecdsa::Signature,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_seed(rand::random());

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;

    let nullifier_vk = groth16_material.nullifier_vk();

    let query = OprfQuery {
        rp_id,
        share_epoch: ShareEpoch::default(),
        action: ark_babyjubjub::Fq::rand(&mut rng),
        nonce,
        current_time_stamp,
        nonce_signature: signature,
    };

    let credential_signature = oprf_test::credentials::random_credential_signature(
        merkle_membership.mt_index,
        current_time_stamp,
        &mut rng,
    );

    let signal_hash = ark_babyjubjub::Fq::rand(&mut rng);

    let args = NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        groth16_material,
        key_material,
        signal_hash,
        rp_nullifier_key,
    };

    let (proof, public, _nullifier) =
        oprf_client::nullifier(services, threshold, args, &mut rng).await?;

    Groth16::verify(&nullifier_vk, &proof.clone().into(), &public).expect("verifies");
    Ok(())
}

fn avg(durations: &[Duration]) -> Duration {
    let n = durations.len();
    if n != 0 {
        let total = durations.iter().sum::<Duration>();
        total / n as u32
    } else {
        Duration::ZERO
    }
}

async fn health_check(health_url: String) {
    loop {
        if reqwest::get(&health_url).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tracing::info!("healthy: {health_url}");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("info");
    let config = OprfDevClientConfig::parse();
    tracing::info!(
        "starting with nullifier_num: {} and nullifier_interval: {:?}",
        config.nullifier_num,
        config.nullifier_interval
    );

    tracing::info!("health check for all peers and SC Mock...");
    let health_checks = config
        .services
        .iter()
        .map(|service| health_check(format!("{service}/health")))
        .collect::<JoinSet<_>>();

    tokio::time::timeout(Duration::from_secs(5), health_checks.join_all())
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let rp_signing_key = k256::SecretKey::random(&mut rand::thread_rng());
    let rp_pk = Types::EcDsaPubkeyCompressed::try_from(rp_signing_key.public_key())?;
    let rp_signing_key = k256::ecdsa::SigningKey::from(rp_signing_key);
    let rp_id = rp_registry_scripts::init_key_gen(
        &config.chain_ws_rpc_url,
        config.key_gen_contract,
        rp_pk,
        config.taceo_private_key.expose_secret(),
    )?;

    tracing::info!("crating account..");
    let key_material = world_id_protocol_mock::fetch_key_material()?;
    world_id_protocol_mock::create_account(
        &config.chain_ws_rpc_url,
        &config.account_registry_contract.to_string(),
    );

    let merkle_proof = reqwest::get(format!(
        "{}/proof/{}",
        config.auth_tree_indexer_api_url, config.account_id
    ))
    .await?
    .json::<InclusionProofResponse>()
    .await?;
    let merkle_membership = MerkleMembership::from(merkle_proof);

    let ws = WsConnect::new(config.chain_ws_rpc_url);
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = KeyGen::new(config.key_gen_contract, provider.clone());

    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            interval.tick().await;
            let maybe_rp_nullifier_key =
                contract.getRpNullifierKey(rp_id.into_inner()).call().await;
            if let Ok(rp_nullifier_key) = maybe_rp_nullifier_key {
                return eyre::Ok(RpNullifierKey::new(rp_nullifier_key.try_into()?));
            }
        }
    })
    .await
    .context("could not finish key-gen in 5 seconds")?
    .context("while polling RP key")?;

    let mut nullifier_results = JoinSet::new();
    let durations = Arc::new(Mutex::new(Vec::new()));

    let durations_clone = Arc::clone(&durations);
    let mut stats_interval = tokio::time::interval(config.stats_interval);
    tokio::spawn(async move {
        loop {
            stats_interval.tick().await;
            let durations = durations_clone.lock();
            let n = durations.len();
            let avg = avg(&durations);
            tracing::info!("nullifiers: {n} avg duration: {avg:?}");
        }
    });

    for _ in 0..config.nullifier_num {
        let durations_clone = Arc::clone(&durations);
        let services = config.services.clone();
        let threshold = config.threshold;
        let merkle_membership = merkle_membership.clone();
        let key_material = key_material.clone();
        let nonce = ark_babyjubjub::Fq::rand(&mut rand::thread_rng());
        let current_time_stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_secs();

        let mut msg = Vec::new();
        msg.extend(nonce.into_bigint().to_bytes_le());
        msg.extend(current_time_stamp.to_le_bytes());
        let signature = rp_signing_key.sign(&msg);
        nullifier_results.spawn(async move {
            let start = Instant::now();
            run_nullifier(
                &services,
                threshold,
                rp_id,
                rp_nullifier_key,
                merkle_membership,
                key_material,
                nonce,
                current_time_stamp,
                signature,
            )
            .await
            .expect("does not fail");
            let duration = start.elapsed();
            durations_clone.lock().push(duration);
        });
        tokio::time::sleep(config.nullifier_interval).await;
    }

    nullifier_results.join_all().await;

    let durations = durations.lock();
    let n = durations.len();
    assert_eq!(n, config.nullifier_num);
    let avg = avg(&durations);
    tracing::info!("completed all nullifiers, avg duration: {avg:?}",);

    Ok(())
}
