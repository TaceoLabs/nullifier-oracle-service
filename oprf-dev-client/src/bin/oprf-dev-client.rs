use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use ark_ff::{PrimeField as _, UniformRand as _};
use clap::Parser;
use eyre::Context;
use oprf_client::{
    MAX_DEPTH, MerkleMembership, NullifierArgs, OprfQuery, UserKeyMaterial, groth16::Groth16,
    zk::Groth16Material,
};
use oprf_test::world_id_protocol_mock::{self, ProofResponse};
use oprf_types::{
    MerkleEpoch, RpId, ShareEpoch, crypto::RpNullifierKey, sc_mock::SignNonceResponse,
};
use parking_lot::Mutex;
use rand::SeedableRng;
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

    /// Chain URL.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_URL",
        default_value = "http://localhost:6789"
    )]
    pub chain_url: String,

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
        default_value = "http://localhost:8585"
    )]
    pub auth_tree_indexer_api_url: String,

    /// AccountRegistry account id
    #[clap(long, env = "OPRF_DEV_CLIENT_ACCOUNT_ID", default_value = "1")]
    pub account_id: usize,
}

async fn run_nullifier(
    services: &[String],
    threshold: usize,
    chain_url: &str,
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_seed(rand::random());
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);

    let SignNonceResponse {
        signature,
        current_time_stamp,
    } = oprf_test::sc_mock::sign_nonce(chain_url, rp_id, nonce).await?;

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
    let mut health_checks = config
        .services
        .iter()
        .map(|service| health_check(format!("{service}/health")))
        .collect::<JoinSet<_>>();
    let sc_health_url = format!("{}/health", config.chain_url);
    health_checks.spawn(health_check(sc_health_url));

    tokio::time::timeout(Duration::from_secs(5), health_checks.join_all())
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    tracing::info!("register_rp");
    let (rp_id, rp_nullifier_key) = oprf_test::sc_mock::register_rp(&config.chain_url).await?;

    let key_material = world_id_protocol_mock::fetch_key_material()?;

    let merkle_proof = reqwest::get(format!(
        "{}/proof/{}",
        config.auth_tree_indexer_api_url, config.account_id
    ))
    .await?
    .json::<ProofResponse>()
    .await?;
    // TODO cleanup conversion of merkle_proof/merkle_membership
    let depth = merkle_proof.proof.len() as u64;
    let mut siblings = merkle_proof
        .proof
        .into_iter()
        .map(|p| ark_babyjubjub::Fq::from_be_bytes_mod_order(&p.to_be_bytes::<32>()))
        .collect::<Vec<_>>();
    // pad sibling to max depth
    for _ in 0..MAX_DEPTH as u64 - depth {
        siblings.push(ark_babyjubjub::Fq::default());
    }
    let merkle_membership = MerkleMembership {
        epoch: MerkleEpoch::default(),
        root: merkle_proof.root.into(),
        depth, // send actual depth of contract merkle tree
        mt_index: merkle_proof.leaf_index,
        siblings: siblings.try_into().unwrap(),
    };

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
        let chain_url = config.chain_url.clone();
        let merkle_membership = merkle_membership.clone();
        let key_material = key_material.clone();
        nullifier_results.spawn(async move {
            let start = Instant::now();
            run_nullifier(
                &services,
                threshold,
                &chain_url,
                rp_id,
                rp_nullifier_key,
                merkle_membership,
                key_material,
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
