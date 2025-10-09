#![deny(missing_docs)]
//! OPRF Peer Service
//!
//! This crate implements the main entry point, configuration, metrics, telemetry,
//! and service components for an OPRF peer.
//!
//! TODO TOP LEVEL DOCUMENTATION
//!
//! # Key Components
//! - `AppState`: Holds shared state for Axum, including OPRF service and chain watcher.
//! - `start()`: Main async entry point to start the service, initialize crypto, secret manager, and spawn Axum server and background tasks.
//! - `spawn_shutdown_task()`: Helper to create a `CancellationToken` for coordinated shutdown.
//! - `default_shutdown_signal()`: Default shutdown signal using CTRL+C or UNIX terminate signals.
//!
//! # Modules
//! - `config`: Configuration via environment variables or CLI.
//! - `metrics`: Metrics keys and helpers.
//! - `services`: Core services like OPRF evaluation, chain watcher, and secret management.
//! - `api`: REST API routes.
use std::{fs::File, str::FromStr, sync::Arc};

use alloy::{network::EthereumWallet, signers::local::PrivateKeySigner};
use ark_serde_compat::groth16::Groth16VerificationKey;
use axum::extract::FromRef;
use eyre::Context;
use oprf_types::crypto::PartyId;
use secrecy::ExposeSecret;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::services::{
    crypto_device::CryptoDevice,
    event_handler::ChainEventHandler,
    key_event_watcher::{KeyGenEventListenerService, alloy_key_gen_watcher::AlloyKeyGenWatcher},
    merkle_watcher::{MerkleWatcherService, alloy_merkle_watcher::AlloyMerkleWatcher},
    oprf::OprfService,
    secret_manager::aws::AwsSecretManager,
};

pub(crate) mod api;
pub mod config;
pub mod metrics;
pub(crate) mod services;

/// Main application state for the OPRF-Peer used for Axum.
///
/// If Axum should be able to extract services, it should be added to
/// the `AppState`.
#[derive(Clone)]
pub(crate) struct AppState {
    oprf_service: OprfService,
    party_id: PartyId,
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

/// Main entry point for the OPRF-Service.
/// TODO better docs
pub async fn start(
    config: config::OprfPeerConfig,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    // install rustls crypto provider
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::warn!("cannot install rustls crypto provider!");
        tracing::warn!("we continue but this should not happen...");
    };
    let config = Arc::new(config);

    tracing::info!(
        "loading Groth16 verification key from: {:?}",
        config.user_verification_key_path
    );
    let vk = File::open(&config.user_verification_key_path)
        .context("while opening file to verification key")?;
    let vk: Groth16VerificationKey = serde_json::from_reader(vk)
        .context("while parsing Groth16 verification key for user proof")?;

    // Load the secret manager. For now we only support AWS.
    // For local development, we also allow to load secret from file. Still the local secret-manager will assert that we run in Dev environment
    let secret_manager = Arc::new(AwsSecretManager::init(Arc::clone(&config)).await);

    tracing::info!("init crypto device..");
    let crypto_device = Arc::new(
        CryptoDevice::init(secret_manager)
            .await
            .context("while initiating crypto-device")?,
    );

    let cancellation_token = spawn_shutdown_task(shutdown_signal);

    tracing::info!("connecting to wallet..");
    let private_key = PrivateKeySigner::from_str(config.wallet_private_key.expose_secret())
        .context("while reading wallet private key")?;
    let wallet = EthereumWallet::from(private_key);

    tracing::info!("spawning chain event handler..");
    let key_gen_watcher: KeyGenEventListenerService = Arc::new(
        AlloyKeyGenWatcher::init(&config.chain_ws_rpc_url, config.key_gen_contract, wallet)
            .await
            .context("while spawning alloy key-gen watcher")?,
    );

    tracing::info!("loading party id..");
    let party_id = key_gen_watcher
        .fetch_party_id()
        .await
        .context("while loading partyID")?;
    tracing::info!("we are party id: {party_id}");

    tracing::info!("spawning merkle watcher..");
    let merkle_watcher: MerkleWatcherService = Arc::new(
        AlloyMerkleWatcher::init(
            config.account_registry_contract,
            &config.chain_ws_rpc_url,
            config.max_merkle_store_size,
            config.chain_epoch_max_difference,
        )
        .await
        .context("while starting merkle watcher")?,
    );

    tracing::info!("init oprf-service...");
    let oprf_service = OprfService::init(
        Arc::clone(&crypto_device),
        Arc::clone(&merkle_watcher),
        vk.into(),
        config.request_lifetime,
        config.session_cleanup_interval,
        config.max_merkle_depth,
        config.current_time_stamp_max_difference,
        config.signature_history_cleanup_interval,
    );

    let event_handler = ChainEventHandler::spawn(
        party_id,
        key_gen_watcher,
        Arc::clone(&crypto_device),
        cancellation_token.clone(),
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    let axum_rest_api = api::new_app(party_id, oprf_service);

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
        "waiting for shutdown of services (max wait time {} as secs)..",
        humantime::format_duration(config.max_wait_time_shutdown)
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
    use std::collections::BTreeMap;
    use std::time::SystemTime;
    use std::{collections::HashMap, fs::File, path::PathBuf, time::Duration};

    use ark_ff::{BigInteger as _, PrimeField as _, UniformRand};
    use ark_serde_compat::groth16::Groth16VerificationKey;
    use axum_test::TestServer;
    use k256::ecdsa::signature::SignerMut;
    use oprf_client::zk::Groth16Material;
    use oprf_client::{MAX_DEPTH, MerkleMembership, OprfQuery};
    use oprf_core::ddlog_equality::DLogEqualityCommitments;
    use oprf_core::proof_input_gen::query::QueryProofInput;
    use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
    use oprf_types::crypto::RpNullifierKey;
    use oprf_types::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch};
    use rand::Rng as _;
    use uuid::Uuid;

    use crate::services::crypto_device::dlog_storage::RpMaterial;
    use crate::services::merkle_watcher::test::TestMerkleWatcher;
    use crate::services::{
        crypto_device::{CryptoDevice, DLogShare, PeerPrivateKey},
        secret_manager::test::TestSecretManager,
    };

    use super::*;

    struct TestSetup {
        server: TestServer,
        oprf_service: OprfService,
        oprf_req: OprfRequest,
        challenge_req: ChallengeRequest,
    }

    impl TestSetup {
        async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

            let key_material = oprf_test::credentials::random_user_keys(&mut rng);
            let siblings: [ark_babyjubjub::Fq; MAX_DEPTH] =
                array::from_fn(|_| ark_babyjubjub::Fq::rand(&mut rng));
            let mt_index = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
            let merkle_root = MerkleRoot::new(QueryProofInput::merkle_root_from_pks(
                &key_material.pk_batch.clone().into_proof_input(),
                &siblings,
                mt_index,
            ));
            let merkle_epoch = MerkleEpoch::new(0);
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

            let groth16_material = Groth16Material::new(
                dir.join("../circom/main/OPRFQueryProof.zkey"),
                dir.join("../circom/main/OPRFNullifierProof.zkey"),
            )?;

            let merkle_membership = MerkleMembership {
                epoch: merkle_epoch,
                depth: MAX_DEPTH as u64, // TODO fix me
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
                groth16_material,
                oprf_query,
                key_material,
                request_id,
                &mut rng,
            )?;
            let oprf_req = signed_query.get_request();
            let challenge_req = ChallengeRequest {
                request_id,
                challenge: DLogEqualityCommitments::new(
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                    ark_babyjubjub::EdwardsAffine::rand(&mut rng),
                ),
                rp_identifier: NullifierShareIdentifier { rp_id, share_epoch },
            };

            let secret_manager = Arc::new(TestSecretManager::new(
                PeerPrivateKey::from(ark_babyjubjub::Fr::rand(&mut rng)),
                HashMap::from([(
                    rp_id,
                    RpMaterial::new(
                        HashMap::from([(
                            ShareEpoch::default(),
                            DLogShare::from(ark_babyjubjub::Fr::rand(&mut rng)),
                        )]),
                        rp_public_key.into(),
                        RpNullifierKey::new(rng.r#gen()),
                    ),
                )]),
            ));
            let crypto_device = Arc::new(CryptoDevice::init(secret_manager).await?);
            let max_merkle_store_size = 10;
            let chain_epoch_max_difference = 10;
            let merkle_watcher = Arc::new(TestMerkleWatcher::new(
                BTreeMap::from([(merkle_epoch, merkle_root)]),
                max_merkle_store_size,
                chain_epoch_max_difference,
            )?);
            let user_verification_key_path = dir.join("../circom/main/OPRFQueryProof.vk.json");
            let vk = File::open(&user_verification_key_path)?;
            let vk: Groth16VerificationKey = serde_json::from_reader(vk)?;
            let request_lifetime = Duration::from_secs(5 * 60);
            let session_cleanup_interval = Duration::from_secs(30);
            let max_merkle_depth = 30;
            let current_time_stamp_max_difference = Duration::from_secs(60);
            let signature_history_cleanup_interval = Duration::from_secs(60);
            let oprf_service = OprfService::init(
                crypto_device,
                merkle_watcher,
                vk.into(),
                request_lifetime,
                session_cleanup_interval,
                max_merkle_depth,
                current_time_stamp_max_difference,
                signature_history_cleanup_interval,
            );
            let server = api::new_test_app(PartyId::from(0), oprf_service.clone());

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
        req.proof.a = req.proof.c;
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
    async fn test_init_bad_signature() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.signature = k256::ecdsa::Signature::from_slice(&[42u8; 64])?;
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
    async fn test_init_unknown_merkle_epoch() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let unknown_merkle_epoch = MerkleEpoch::new(rand::random());
        let mut req = setup.oprf_req;
        req.merkle_epoch = unknown_merkle_epoch;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text(format!("Unknown merkle epoch: {unknown_merkle_epoch}"));
        res.assert_status_bad_request();
        Ok(())
    }

    #[tokio::test]
    async fn test_init_wrong_merkle_depth() -> eyre::Result<()> {
        let setup = TestSetup::new().await?;
        let mut req = setup.oprf_req;
        req.merkle_depth = u64::MAX;
        let res = setup
            .server
            .post("/api/v1/init")
            .json(&req)
            .expect_failure()
            .await;
        res.assert_text("merkle tree depth greater than max: 30");
        res.assert_status_bad_request();
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
        req.current_time_stamp = 42;
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
