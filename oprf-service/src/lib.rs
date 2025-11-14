#![deny(missing_docs)]
//! This crate implements a peer node for the distributed OPRF (Oblivious Pseudo-Random Function)
//! nullifier oracle service. The service participates in multi-party key generation and provides
//! partial OPRF evaluations for World ID protocol nullifiers.
//!
//! # Overview
//!
//! The OPRF peer:
//! - Participates in distributed secret generation with other peers
//! - Evaluates partial OPRF shares for authenticated clients
//! - Monitors on-chain events for key generation and merkle root updates
//! - Stores and manages cryptographic material securely via agnostic Secrets Manager (currently only AWS supported).
//!
//! For details on the OPRF protocol, see the [design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf).
use std::{fs::File, future::Future, str::FromStr, sync::Arc};

use alloy::{network::EthereumWallet, primitives::Address, signers::local::PrivateKeySigner};
use ark_bn254::Bn254;
use axum::extract::FromRef;
use circom_types::groth16::VerificationKey;
use eyre::Context;
use groth16_material::circom::CircomGroth16MaterialBuilder;
use oprf_types::crypto::PartyId;
use secrecy::ExposeSecret;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::services::{
    event_handler::ChainEventHandler,
    key_event_watcher::{KeyGenEventListenerService, alloy_key_gen_watcher::AlloyKeyGenWatcher},
    merkle_watcher::{MerkleWatcherService, alloy_merkle_watcher::AlloyMerkleWatcher},
    oprf::OprfService,
    secret_manager::SecretManagerService,
};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub mod rp_registry;
pub(crate) mod services;

pub use services::rp_material_store::RpMaterialStore;
pub use services::secret_manager::SecretManager;
pub use services::secret_manager::StoreDLogShare;
pub use services::secret_manager::aws::AwsSecretManager;

/// Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary.
pub fn version_info() -> String {
    format!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version::git_version!(fallback = "UNKNOWN"))
    )
}

/// Main application state for the OPRF-Peer used for Axum.
///
/// If Axum should be able to extract services, it should be added to
/// the `AppState`.
#[derive(Clone)]
pub(crate) struct AppState {
    oprf_service: OprfService,
    party_id: PartyId,
    wallet_address: Address,
}

impl FromRef<AppState> for OprfService {
    fn from_ref(input: &AppState) -> Self {
        input.oprf_service.clone()
    }
}

impl FromRef<AppState> for PartyId {
    fn from_ref(input: &AppState) -> Self {
        input.party_id
    }
}

/// Loads the private key from the provided secret-manager and creates a Private Key for usage with alloy.
///
/// The loaded secret will be set to all zeroes and dropped.
async fn load_wallet_private_key(
    secret_manager: &SecretManagerService,
) -> eyre::Result<PrivateKeySigner> {
    tracing::info!("loading ETH private key from secret-manager..");
    let mut wallet_private_key_str = secret_manager
        .load_or_insert_wallet_private_key()
        .await
        .context("while loading ETH private key from secret-manager")?;

    tracing::info!("connecting to wallet..");
    let wallet_private_key = PrivateKeySigner::from_str(wallet_private_key_str.expose_secret())
        .context("while reading wallet private key")?;
    let address = wallet_private_key.address();
    tracing::info!("my wallet address: {address}");
    // set private key to all zeroes
    wallet_private_key_str.zeroize();
    Ok(wallet_private_key)
}

/// Main entry point for the OPRF service.
///
/// Initializes all services, loads cryptographic material, and starts:
/// - The Axum HTTP server for API endpoints
/// - Chain event watcher for key generation
/// - Merkle root watcher for account registry
/// - Background cleanup tasks
///
/// The function blocks until the shutdown signal is triggered or an error occurs.
///
/// # Arguments
/// * `config` - Service configuration from CLI or environment
/// * `shutdown_signal` - Future that completes when shutdown is requested
///
/// # Errors
/// Returns an error if:
/// - Cryptographic material cannot be loaded
/// - Blockchain connections fail
/// - Secret manager initialization fails
/// - Server binding fails
pub async fn start(
    config: config::OprfPeerConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    tracing::info!(
        "loading Groth16 verification key from: {:?}",
        config.user_verification_key_path
    );
    let vk = File::open(&config.user_verification_key_path)
        .context("while opening file to verification key")?;
    let vk: VerificationKey<Bn254> = serde_json::from_reader(vk)
        .context("while parsing Groth16 verification key for user proof")?;

    let private_key = load_wallet_private_key(&secret_manager)
        .await
        .context("while loading ETH private key from secret-manager")?;

    let wallet_address = private_key.address();
    let wallet = EthereumWallet::from(private_key);

    tracing::info!("spawning chain event listener..");
    let key_gen_watcher: KeyGenEventListenerService = Arc::new(
        AlloyKeyGenWatcher::new(
            config.chain_ws_rpc_url.expose_secret(),
            config.rp_registry_contract,
            wallet,
        )
        .await
        .context("while connecting to RpRegistry contract")?,
    );

    tracing::info!("loading party id..");
    let party_id = key_gen_watcher
        .load_party_id()
        .await
        .context("while loading partyId")?;
    tracing::info!("we are party id: {party_id}");

    tracing::info!("init RpMaterialStore..");
    let rp_material_store = secret_manager
        .load_secrets()
        .await
        .context("while loading secrets from secret-manager")?;

    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    tracing::info!("spawning merkle watcher..");
    let merkle_watcher: MerkleWatcherService = Arc::new(
        AlloyMerkleWatcher::init(
            config.account_registry_contract,
            config.chain_ws_rpc_url.expose_secret(),
            config.max_merkle_store_size,
        )
        .await
        .context("while starting merkle watcher")?,
    );

    tracing::info!("init oprf-service...");
    let oprf_service = OprfService::init(
        rp_material_store.clone(),
        Arc::clone(&merkle_watcher),
        vk.into(),
        config.request_lifetime,
        config.session_cleanup_interval,
        config.current_time_stamp_max_difference,
        config.signature_history_cleanup_interval,
    );

    tracing::info!("spawning chain event handler..");
    let key_gen_material = CircomGroth16MaterialBuilder::new()
        .bbf_inv()
        .bbf_num_2_bits_helper()
        .from_paths(config.key_gen_zkey_path, config.key_gen_witness_graph_path)?;
    let event_handler = ChainEventHandler::spawn(
        key_gen_watcher,
        rp_material_store,
        secret_manager,
        cancellation_token.clone(),
        key_gen_material,
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    let axum_rest_api = api::new_app(party_id, oprf_service, wallet_address);

    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map(|x| x.to_string())
                .unwrap_or(String::from("invalid addr"))
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = axum::serve(listener, axum_rest_api)
            .with_graceful_shutdown(async move { axum_shutdown_signal.cancelled().await })
            .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!("got error from axum: {err:?}");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, async move {
        tokio::join!(server, event_handler.wait())
    })
    .await
    {
        Ok(_) => tracing::info!("successfully finished shutdown in time"),
        Err(_) => tracing::warn!("could not finish shutdown in time"),
    }

    Ok(())
}

/// Spawns a shutdown task and creates an associated [CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html). This task will complete when either the provided shutdown_signal futures completes or if some other tasks cancels the shutdown token. The associated shutdown token will be cancelled either way.
///
/// Waiting for the shutdown token is the preferred way to wait for termination.
fn spawn_shutdown_task(
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> CancellationToken {
    let cancellation_token = CancellationToken::new();
    let task_token = cancellation_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_signal => {
                tracing::info!("Received EXTERNAL shutdown");
                task_token.cancel();
            }
            _ = task_token.cancelled() => {
                tracing::info!("Received INTERNAL shutdown");
            }
        }
    });
    cancellation_token
}

/// The default shutdown signal for the oprf-service. Triggered when pressing CTRL+C on most systems.
pub async fn default_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use std::array;
    use std::time::SystemTime;
    use std::{collections::HashMap, fs::File, path::PathBuf, time::Duration};

    use alloy::primitives::address;
    use ark_ff::{BigInteger as _, PrimeField as _, UniformRand, Zero};
    use axum_test::TestServer;
    use k256::ecdsa::signature::SignerMut;
    use oprf_client::OprfQuery;
    use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogShareShamir};
    use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
    use oprf_types::crypto::RpNullifierKey;
    use oprf_types::{RpId, ShareEpoch};
    use oprf_world_types::api::v1::OprfRequestAuth;
    use oprf_world_types::proof_inputs::query::MAX_PUBLIC_KEYS;
    use oprf_world_types::{MerkleMembership, MerkleRoot, TREE_DEPTH};
    use poseidon2::Poseidon2;
    use rand::Rng as _;
    use uuid::Uuid;

    use crate::services::merkle_watcher::test::TestMerkleWatcher;
    use crate::services::rp_material_store::{RpMaterial, RpMaterialStore};

    use super::*;

    const PK_DS: &[u8] = b"World ID PK";

    fn merkle_root_from_pks(
        pks: &[ark_babyjubjub::EdwardsAffine; MAX_PUBLIC_KEYS],
        siblings: &[ark_babyjubjub::Fq; TREE_DEPTH],
        index: u64,
    ) -> ark_babyjubjub::Fq {
        // Hash pk
        let poseidon2_16 = Poseidon2::<_, 16, 5>::default();
        let mut input = array::from_fn(|_| ark_babyjubjub::Fq::zero());
        input[0] = ark_babyjubjub::Fq::from_be_bytes_mod_order(PK_DS);
        for (i, pk) in pks.iter().enumerate() {
            input[1 + i * 2] = pk.x;
            input[1 + i * 2 + 1] = pk.y;
        }
        let leaf = poseidon2_16.permutation(&input)[1];
        merkle_root(leaf, siblings, index)
    }

    fn merkle_root(
        leaf: ark_babyjubjub::Fq,
        siblings: &[ark_babyjubjub::Fq; TREE_DEPTH],
        mut index: u64,
    ) -> ark_babyjubjub::Fq {
        let mut current_hash = leaf;

        // Merkle chain
        let poseidon2_2 = Poseidon2::<_, 2, 5>::default();
        for s in siblings {
            if index & 1 == 0 {
                current_hash = poseidon2_2.permutation(&[current_hash, *s])[0] + current_hash;
            } else {
                current_hash = poseidon2_2.permutation(&[*s, current_hash])[0] + s;
            }
            index >>= 1;
        }

        current_hash
    }

    struct TestSetup {
        server: TestServer,
        oprf_service: OprfService,
        oprf_req: OprfRequest<OprfRequestAuth>,
        challenge_req: ChallengeRequest,
    }

    impl TestSetup {
        async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

            let key_material = oprf_test::credentials::random_user_keys(&mut rng);
            let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] =
                array::from_fn(|_| ark_babyjubjub::Fq::rand(&mut rng));
            let mt_index = rng.gen_range(0..(1 << TREE_DEPTH)) as u64;
            let merkle_root = MerkleRoot::new(merkle_root_from_pks(
                &key_material.pk_batch.clone().into_inner(),
                &siblings,
                mt_index,
            ));
            let share_epoch = ShareEpoch::default();

            let rp_id = RpId::new(rng.r#gen());
            let rp_secret_key = k256::SecretKey::random(&mut rng);
            let rp_public_key = rp_secret_key.public_key();
            let mut rp_signing_key = k256::ecdsa::SigningKey::from(rp_secret_key);

            let nonce = ark_babyjubjub::Fq::rand(&mut rng);
            let current_time_stamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time is after unix epoch")
                .as_secs();
            let mut msg = Vec::new();
            msg.extend(nonce.into_bigint().to_bytes_le());
            msg.extend(current_time_stamp.to_le_bytes());
            let signature = rp_signing_key.sign(&msg);

            let query_material = oprf_client::load_embedded_query_key();

            let merkle_membership = MerkleMembership {
                root: merkle_root,
                mt_index,
                siblings,
            };
            let oprf_query = OprfQuery {
                rp_id,
                share_epoch,
                action: ark_babyjubjub::Fq::rand(&mut rng),
                nonce,
                current_time_stamp,
                nonce_signature: signature,
            };
            let credential_signature = oprf_test::credentials::random_credential_signature(
                mt_index,
                current_time_stamp,
                &mut rng,
            );
            let request_id = Uuid::new_v4();
            let signed_query = oprf_client::sign_oprf_query(
                credential_signature,
                merkle_membership,
                &query_material,
                oprf_query,
                key_material,
                request_id,
                &mut rng,
            )?;
            let oprf_req = signed_query.get_request();
            let challenge_req = ChallengeRequest {
                request_id,
                challenge: DLogCommitmentsShamir::new(
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    vec![1, 2, 3],
                ),
                rp_identifier: NullifierShareIdentifier { rp_id, share_epoch },
            };

            let rp_material = RpMaterialStore::new(HashMap::from([(
                rp_id,
                RpMaterial::new(
                    HashMap::from([(
                        ShareEpoch::default(),
                        DLogShareShamir::from(ark_babyjubjub::Fr::rand(&mut rng)),
                    )]),
                    rp_public_key.into(),
                    RpNullifierKey::new(rng.r#gen()),
                ),
            )]));

            let max_merkle_store_size = 10;
            let merkle_watcher = Arc::new(TestMerkleWatcher::new(
                HashMap::from([(merkle_root, 0)]),
                max_merkle_store_size,
            )?);
            let user_verification_key_path = dir.join("../circom/main/query/OPRFQuery.vk.json");
            let vk = File::open(&user_verification_key_path)?;
            let vk: VerificationKey<Bn254> = serde_json::from_reader(vk)?;
            let request_lifetime = Duration::from_secs(5 * 60);
            let session_cleanup_interval = Duration::from_secs(30);
            let current_time_stamp_max_difference = Duration::from_secs(60);
            let signature_history_cleanup_interval = Duration::from_secs(60);
            let oprf_service = OprfService::init(
                rp_material,
                merkle_watcher,
                vk.into(),
                request_lifetime,
                session_cleanup_interval,
                current_time_stamp_max_difference,
                signature_history_cleanup_interval,
            );
            let server = api::new_test_app(
                PartyId::from(0),
                oprf_service.clone(),
                address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), // random anvil address
            );

            Ok(Self {
                server,
                oprf_service,
                oprf_req,
                challenge_req,
            })
        }
    }

    #[tokio::test]
    async fn test_init() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_init_bad_proof() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.auth.proof.pi_a = req.auth.proof.pi_c;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("invalid proof");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_blinded_query_identity_is_bad_request() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.blinded_query = ark_babyjubjub::EdwardsAffine::zero();
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("blinded query not allowed to be identity");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_bad_signature() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.auth.signature = k256::ecdsa::Signature::from_slice(&[42u8; 64])?;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("Invalid signature: signature error");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_unknown_rp_id() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let unknown_rp_id = RpId::new(rand::random());
        let mut req = setup.oprf_req;
        req.rp_identifier.rp_id = unknown_rp_id;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!("Cannot find RP with id: {unknown_rp_id}"));
        res.assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_unknown_share_epoch() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let unknown_share_epoch = ShareEpoch::new(rand::random());
        let mut req = setup.oprf_req;
        req.rp_identifier.share_epoch = unknown_share_epoch;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!(
            "Cannot find share with epoch {} for RP with id: {}",
            req.rp_identifier.share_epoch, req.rp_identifier.rp_id,
        ));
        res.assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_duplicate_signature() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("duplicate signature");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_bad_time_stamp() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.auth.current_time_stamp = 42;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("the time stamp difference is too large");
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        let req = setup.challenge_req;
        setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .await
            .assert_status_ok();
        assert!(
            !setup
                .oprf_service
                .session_store
                .contains_key(req.request_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_finish_without_init() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.challenge_req;
        setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .expect_failure()
            .await
            .assert_status_not_found();
        Ok(())
    }

    #[tokio::test]
    async fn test_finish_unknown_share_epoch() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let req = setup.oprf_req;
        setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .await
            .assert_status_ok();
        let unknown_share_epoch = ShareEpoch::new(rand::random());
        let mut req = setup.challenge_req;
        req.rp_identifier.share_epoch = unknown_share_epoch;
        let res = setup
            .server
            .post("/api/v1/finish")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!(
            "Cannot find share with epoch {} for RP with id: {}",
            req.rp_identifier.share_epoch, req.rp_identifier.rp_id,
        ));
        res.assert_status_not_found();
        Ok(())
    }
}
