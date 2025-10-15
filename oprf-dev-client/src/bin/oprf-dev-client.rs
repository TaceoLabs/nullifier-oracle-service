use std::{
    path::PathBuf,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use alloy::{network::EthereumWallet, primitives::Address, signers::local::PrivateKeySigner};
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use clap::{Parser, Subcommand};
use eyre::Context as _;
use k256::ecdsa::signature::Signer as _;
use oprf_client::{
    MerkleMembership, NullifierArgs, OprfQuery, SignedOprfQuery, UserKeyMaterial, groth16::Groth16,
    zk::Groth16Material,
};
use oprf_service::rp_registry::{RpRegistry, Types};
use oprf_test::{MOCK_RP_SECRET_KEY, rp_registry_scripts, world_id_protocol_mock::Authenticator};
use oprf_test::{TACEO_ADMIN_PRIVATE_KEY, world_id_protocol_mock::InclusionProofResponse};
use oprf_types::{RpId, ShareEpoch, api::v1::OprfRequest, crypto::RpNullifierKey};
use parking_lot::Mutex;
use rand::{CryptoRng, Rng, SeedableRng};
use secrecy::{ExposeSecret, SecretString};
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Parser, Debug)]
pub struct StressTestCommand {
    /// The amount of nullifiers to generate
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub nullifier_num: usize,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub sequential: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Test,
    StressTest(StressTestCommand),
}

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
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
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

    /// AuthTreeIndexer address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_AUTH_TREE_INDEXER_API_URL",
        default_value = "http://localhost:8080"
    )]
    pub auth_tree_indexer_api_url: String,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: Option<u128>,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

fn nullifier_args<R: Rng + CryptoRng>(
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    rng: &mut R,
) -> eyre::Result<NullifierArgs> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;

    let nonce = ark_babyjubjub::Fq::rand(rng);
    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();
    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = k256::ecdsa::SigningKey::from(MOCK_RP_SECRET_KEY.clone()).sign(&msg);

    let query = OprfQuery {
        rp_id,
        share_epoch: ShareEpoch::default(),
        action: ark_babyjubjub::Fq::rand(rng),
        nonce,
        current_time_stamp,
        nonce_signature: signature,
    };

    let credential_signature = oprf_test::credentials::random_credential_signature(
        merkle_membership.mt_index,
        current_time_stamp,
        rng,
    );

    let signal_hash = ark_babyjubjub::Fq::rand(rng);

    let args = NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        groth16_material,
        key_material,
        signal_hash,
        rp_nullifier_key,
    };
    Ok(args)
}

#[allow(clippy::too_many_arguments)]
async fn run_nullifier(
    services: &[String],
    threshold: usize,
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let args = nullifier_args(
        rp_id,
        rp_nullifier_key,
        merkle_membership,
        key_material,
        &mut rng,
    )?;
    let nullifier_vk = args.groth16_material.nullifier_vk();

    let (proof, public, _nullifier) =
        oprf_client::nullifier(services, threshold, args, &mut rng).await?;

    Groth16::verify(&nullifier_vk, &proof.into(), &public).expect("verifies");
    Ok(())
}

fn prepare_nullifier_stress_test_oprf_request(
    rp_id: RpId,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
) -> eyre::Result<(SignedOprfQuery, OprfRequest)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;

    let nonce = ark_babyjubjub::Fq::rand(&mut rand::thread_rng());
    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();
    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = k256::ecdsa::SigningKey::from(MOCK_RP_SECRET_KEY.clone()).sign(&msg);

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

    let request_id = Uuid::new_v4();
    let signed_query = oprf_client::sign_oprf_query(
        credential_signature,
        merkle_membership,
        groth16_material,
        query,
        key_material,
        request_id,
        &mut rng,
    )?;

    let req = signed_query.get_request();

    Ok((signed_query, req))
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
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

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

    let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)?;
    let wallet = EthereumWallet::from(private_key);
    let rp_registry = RpRegistry::init(
        &config.chain_ws_rpc_url,
        config.key_gen_contract,
        wallet.clone(),
    )
    .await?;

    let (rp_id, rp_nullifier_key) = if let Some(rp_id) = config.rp_id {
        let rp_id = RpId::new(rp_id);
        let rp_nullifier_key = rp_registry.fetch_rp_nullifier_key(rp_id).await?;
        (rp_id, rp_nullifier_key)
    } else {
        let rp_pk = Types::EcDsaPubkeyCompressed::try_from(MOCK_RP_SECRET_KEY.public_key())?;
        let rp_id = rp_registry_scripts::init_key_gen(
            &config.chain_ws_rpc_url,
            config.key_gen_contract,
            rp_pk,
            config.taceo_private_key.expose_secret(),
        )?;
        tracing::info!("registered rp with rp_id: {rp_id}");

        let rp_nullifier_key = rp_registry.fetch_rp_nullifier_key(rp_id).await?;
        (rp_id, rp_nullifier_key)
    };

    tracing::info!("creating account..");
    let mut authenticator = Authenticator::new(
        &rand::random::<[u8; 32]>(),
        &config.chain_ws_rpc_url,
        config.account_registry_contract,
        wallet,
    )
    .await?;
    let key_material = authenticator.create_account().await?;
    let account_idx = authenticator.account_index().await?;

    let merkle_proof = reqwest::get(format!(
        "{}/proof/{account_idx}",
        config.auth_tree_indexer_api_url
    ))
    .await?
    .json::<InclusionProofResponse>()
    .await?;
    let merkle_membership = MerkleMembership::from(merkle_proof);

    match config.command {
        Command::Test => {
            tracing::info!("running single nullifier");
            run_nullifier(
                &config.services,
                config.threshold,
                rp_id,
                rp_nullifier_key,
                merkle_membership,
                key_material,
            )
            .await?;
            tracing::info!("nullifier successful");
        }
        Command::StressTest(cmd) => {
            tracing::info!("preparing requests..");
            let mut oprf_queries = Vec::with_capacity(cmd.nullifier_num);
            let mut init_requests = Vec::with_capacity(cmd.nullifier_num);
            for _ in 0..cmd.nullifier_num {
                let (query, req) = prepare_nullifier_stress_test_oprf_request(
                    rp_id,
                    merkle_membership.clone(),
                    key_material.clone(),
                )?;
                oprf_queries.push(query);
                init_requests.push(req);
            }

            let mut init_results = JoinSet::new();
            let durations = Arc::new(Mutex::new(Vec::with_capacity(cmd.nullifier_num)));
            let client = reqwest::Client::new();

            tracing::info!("start sending init requests..");
            let start = Instant::now();
            for req in init_requests {
                let client = client.clone();
                let durations_clone = Arc::clone(&durations);
                let services = config.services.clone();
                let threshold = config.threshold;
                init_results.spawn(async move {
                    let init_start = Instant::now();
                    let sessions =
                        oprf_client::nonblocking::init_sessions(&client, &services, threshold, req)
                            .await?;
                    let duration = init_start.elapsed();
                    durations_clone.lock().push(duration);
                    eyre::Ok(sessions)
                });
                if cmd.sequential {
                    init_results.join_next().await;
                }
            }
            let sessions = init_results.join_all().await;
            let duration = start.elapsed();
            let throughput = cmd.nullifier_num as f64 / duration.as_secs_f64();
            {
                let durations = durations.lock();
                assert_eq!(durations.len(), cmd.nullifier_num);
                let init_avg = avg(&durations);
                tracing::info!(
                    "init req - total time: {duration:?} avg: {init_avg:?} throughput: {throughput} req/s"
                );
            }

            let sessions = sessions.into_iter().collect::<eyre::Result<Vec<_>>>()?;
            let finish_requests = sessions
                .iter()
                .zip(oprf_queries)
                .map(|(sessions, query)| {
                    Ok(
                        oprf_client::compute_challenges(query, sessions, rp_nullifier_key)?
                            .get_request(),
                    )
                })
                .collect::<eyre::Result<Vec<_>>>()?;

            let mut finish_results = JoinSet::new();
            let durations = Arc::new(Mutex::new(Vec::with_capacity(cmd.nullifier_num)));
            let client = reqwest::Client::new();

            tracing::info!("start sending finish requests..");
            let start = Instant::now();
            for (sessions, req) in sessions.into_iter().zip(finish_requests) {
                let client = client.clone();
                let durations_clone = Arc::clone(&durations);
                finish_results.spawn(async move {
                    let finish_start = Instant::now();
                    let _responses =
                        oprf_client::nonblocking::finish_sessions(&client, sessions, req).await?;
                    let duration = finish_start.elapsed();
                    durations_clone.lock().push(duration);
                    eyre::Ok(())
                });
                if cmd.sequential {
                    finish_results.join_next().await;
                }
            }
            finish_results.join_all().await;
            let duration = start.elapsed();
            let throughput = cmd.nullifier_num as f64 / duration.as_secs_f64();
            {
                let durations = durations.lock();
                assert_eq!(durations.len(), cmd.nullifier_num);
                let init_avg = avg(&durations);
                tracing::info!(
                    "finish req - total time: {duration:?} avg: {init_avg:?} throughput: {throughput} req/s"
                );
            }
        }
    }

    Ok(())
}
