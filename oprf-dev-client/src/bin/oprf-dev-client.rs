use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr as _,
    time::{Duration, Instant, SystemTime},
};

use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use clap::{Parser, Subcommand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::Context as _;
use k256::ecdsa::signature::Signer as _;
use oprf_client::{NullifierArgs, OprfQuery, SignedOprfQuery, groth16::Groth16};
use oprf_service::rp_registry::Types;
use oprf_test::{
    MOCK_RP_SECRET_KEY, RpRegistry, health_checks, rp_registry_scripts, world_id_protocol_mock,
};
use oprf_types::{RpId, ShareEpoch, api::v1::OprfRequest, crypto::RpNullifierKey};
use oprf_world_types::{MerkleMembership, UserKeyMaterial, api::v1::OprfRequestAuth};
use oprf_zk::{
    Groth16Material, NULLIFIER_FINGERPRINT, NULLIFIER_GRAPH_BYTES, QUERY_FINGERPRINT,
    QUERY_GRAPH_BYTES,
};
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

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub skip_checks: bool,
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

    /// The Address of the RpRegistry contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT",
        default_value = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
    )]
    pub rp_registry_contract: Address,

    /// The Address of the AccountRegistry contract.
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
    pub chain_ws_rpc_url: SecretString,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF peers
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// Indexer address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_INDEXER_URL",
        default_value = "http://localhost:8080"
    )]
    pub indexer_url: String,

    /// Timeout for fetching indexer inclusion proof
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_INDEXER_INCLUSION_PROOF_TIMEOUT",
        default_value = "30s",
        value_parser = humantime::parse_duration
    )]
    pub indexer_inclusion_proof_timeout: Duration,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: Option<u128>,

    /// max wait time for init key-gen to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_KEY_GEN_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time_key_gen: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

async fn fetch_rp_nullifier_key(
    rp_id: RpId,
    wallet: &EthereumWallet,
    config: &OprfDevClientConfig,
) -> eyre::Result<RpNullifierKey> {
    tracing::info!("fetching rp_nullifier_key..");
    let ws = WsConnect::new(config.chain_ws_rpc_url.expose_secret());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = RpRegistry::new(config.rp_registry_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let rp_nullifier_key = tokio::time::timeout(config.max_wait_time_key_gen, async move {
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
    .context("could not fetch rp nullifier key in time")?
    .context("while polling RP key")?;
    Ok(rp_nullifier_key)
}

fn nullifier_args<R: Rng + CryptoRng>(
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    rng: &mut R,
) -> eyre::Result<NullifierArgs> {
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
    let id_commitment_r = ark_babyjubjub::Fq::rand(rng);

    let args = NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        key_material,
        rp_nullifier_key,
        signal_hash,
        id_commitment_r,
    };
    Ok(args)
}

#[expect(clippy::too_many_arguments)]
async fn run_nullifier(
    services: &[String],
    threshold: usize,
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    query_material: &Groth16Material,
    nullifier_material: &Groth16Material,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let args = nullifier_args(
        rp_id,
        rp_nullifier_key,
        merkle_membership,
        key_material,
        &mut rng,
    )?;
    let nullifier_vk = nullifier_material.pk.vk.clone();

    let (proof, public, _nullifier, _id_commitment) = oprf_client::nullifier(
        services,
        threshold,
        query_material,
        nullifier_material,
        args,
        &mut rng,
    )
    .await?;

    Groth16::verify(&nullifier_vk, &proof.into(), &public).expect("verifies");
    Ok(())
}

fn prepare_nullifier_stress_test_oprf_request(
    rp_id: RpId,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    query_material: &Groth16Material,
) -> eyre::Result<(SignedOprfQuery, OprfRequest<OprfRequestAuth>)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

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
        query_material,
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

#[expect(clippy::too_many_arguments)]
async fn stress_test(
    cmd: StressTestCommand,
    services: &[String],
    threshold: usize,
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    merkle_membership: MerkleMembership,
    key_material: UserKeyMaterial,
    query_material: &Groth16Material,
    nullifier_material: &Groth16Material,
) -> eyre::Result<()> {
    tracing::info!("preparing requests..");
    let mut oprf_queries = HashMap::with_capacity(cmd.nullifier_num);
    let mut init_requests = Vec::with_capacity(cmd.nullifier_num);

    let nullifier_vk = nullifier_material.pk.vk.clone();

    for idx in 0..cmd.nullifier_num {
        let (query, req) = prepare_nullifier_stress_test_oprf_request(
            rp_id,
            merkle_membership.clone(),
            key_material.clone(),
            query_material,
        )?;
        oprf_queries.insert(idx, query);
        init_requests.push(req);
    }

    let mut init_results = JoinSet::new();
    let client = reqwest::Client::new();

    tracing::info!("start sending init requests..");
    let start = Instant::now();
    for (idx, req) in init_requests.into_iter().enumerate() {
        let client = client.clone();
        let services = services.to_vec();
        init_results.spawn(async move {
            let init_start = Instant::now();
            let sessions =
                oprf_client::nonblocking::init_sessions(&client, &services, threshold, req).await?;
            eyre::Ok((idx, sessions, init_start.elapsed()))
        });
        if cmd.sequential {
            init_results.join_next().await;
        }
    }
    let init_results = init_results.join_all().await;
    let init_full_duration = start.elapsed();
    let mut sessions = Vec::with_capacity(cmd.nullifier_num);
    let mut durations = Vec::with_capacity(cmd.nullifier_num);
    for result in init_results {
        match result {
            Ok((idx, session, duration)) => {
                sessions.push((idx, session));
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during init: {err:?}"),
        }
    }
    if durations.len() != cmd.nullifier_num {
        eyre::bail!("init did encounter errors - see logs");
    }
    let init_throughput = cmd.nullifier_num as f64 / init_full_duration.as_secs_f64();
    let init_avg = avg(&durations);

    let mut finish_challenges = sessions
        .iter()
        .map(|(idx, sessions)| {
            eyre::Ok((
                *idx,
                oprf_client::compute_challenges(
                    oprf_queries.remove(idx).expect("is there"),
                    sessions,
                    rp_nullifier_key,
                )?,
            ))
        })
        .collect::<eyre::Result<HashMap<_, _>>>()?;

    let mut finish_results = JoinSet::new();
    let client = reqwest::Client::new();

    tracing::info!("start sending finish requests..");
    durations.clear();
    let start = Instant::now();
    for (idx, sessions) in sessions {
        let client = client.clone();
        let challenge = finish_challenges.remove(&idx).expect("is there");
        finish_results.spawn(async move {
            let finish_start = Instant::now();
            let responses = oprf_client::nonblocking::finish_sessions(
                &client,
                sessions,
                challenge.get_request(),
            )
            .await?;
            let duration = finish_start.elapsed();
            eyre::Ok((responses, challenge, duration))
        });
        if cmd.sequential {
            finish_results.join_next().await;
        }
    }
    let finish_results = finish_results.join_all().await;
    if cmd.skip_checks {
        tracing::info!("got all results - skipping checks");
    } else {
        tracing::info!("got all results - checking nullifiers + proofs");
    }
    let finish_full_duration = start.elapsed();

    // let mut sessions = Vec::with_capacity(cmd.nullifier_num);
    let mut durations = Vec::with_capacity(cmd.nullifier_num);

    let mut rng = rand::thread_rng();
    for result in finish_results {
        match result {
            Ok((responses, challenge, duration)) => {
                if !cmd.skip_checks {
                    let (proof, public, _, _) = oprf_client::verify_challenges(
                        nullifier_material,
                        challenge,
                        responses,
                        ark_babyjubjub::Fq::rand(&mut rng),
                        ark_babyjubjub::Fq::rand(&mut rng),
                        &mut rng,
                    )?;
                    Groth16::verify(&nullifier_vk, &proof.into(), &public)?;
                }
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during finish: {err:?}"),
        }
    }

    tracing::info!(
        "init req - total time: {init_full_duration:?} avg: {init_avg:?} throughput: {init_throughput} req/s"
    );
    let final_throughput = cmd.nullifier_num as f64 / finish_full_duration.as_secs_f64();
    let finish_avg = avg(&durations);
    tracing::info!(
        "finish req - total time: {finish_full_duration:?} avg: {finish_avg:?} throughput: {final_throughput} req/s"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("oprf_dev_client=trace,warn");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let query_material = Groth16Material::from_bytes(
        &std::fs::read(dir.join("../circom/OPRFQueryProof.zkey"))?,
        QUERY_FINGERPRINT.into(),
        QUERY_GRAPH_BYTES,
    )?;
    let nullifier_material = Groth16Material::from_bytes(
        &std::fs::read(dir.join("../circom/OPRFNullifierProof.zkey"))?,
        NULLIFIER_FINGERPRINT.into(),
        NULLIFIER_GRAPH_BYTES,
    )?;

    tracing::info!("health check for all peers...");
    health_checks::services_health_check(&config.services, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key);

    let (rp_id, rp_nullifier_key) = if let Some(rp_id) = config.rp_id {
        let rp_id = RpId::new(rp_id);
        let rp_nullifier_key = fetch_rp_nullifier_key(rp_id, &wallet, &config).await?;
        (rp_id, rp_nullifier_key)
    } else {
        let rp_pk = Types::EcDsaPubkeyCompressed::try_from(MOCK_RP_SECRET_KEY.public_key())?;
        let rp_id = rp_registry_scripts::init_key_gen(
            config.chain_ws_rpc_url.expose_secret(),
            config.rp_registry_contract,
            rp_pk,
            config.taceo_private_key.expose_secret(),
        );
        tracing::info!("registered rp with rp_id: {rp_id}");

        let rp_nullifier_key = fetch_rp_nullifier_key(rp_id, &wallet, &config).await?;
        (rp_id, rp_nullifier_key)
    };

    tracing::info!("creating account..");
    let seed = rand::random::<[u8; 32]>();
    let onchain_signer = PrivateKeySigner::from_bytes(&seed.into())?;
    let offchain_signer_private_key = EdDSAPrivateKey::from_bytes(seed);

    let key_material = world_id_protocol_mock::create_account(
        offchain_signer_private_key,
        &onchain_signer,
        config.chain_ws_rpc_url.expose_secret(),
        config.account_registry_contract,
        wallet.clone(),
    )
    .await?;
    let merkle_membership = world_id_protocol_mock::fetch_inclusion_proof(
        &onchain_signer,
        config.chain_ws_rpc_url.expose_secret(),
        config.account_registry_contract,
        wallet,
        &config.indexer_url,
        Duration::from_secs(10),
    )
    .await?;

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
                &query_material,
                &nullifier_material,
            )
            .await?;
            tracing::info!("nullifier successful");
        }
        Command::StressTest(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                cmd,
                &config.services,
                config.threshold,
                rp_id,
                rp_nullifier_key,
                merkle_membership,
                key_material,
                &query_material,
                &nullifier_material,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
    }

    Ok(())
}
