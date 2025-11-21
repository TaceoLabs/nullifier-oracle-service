// #![deny(missing_docs)]
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

use tokio::signal;
use tokio_util::sync::CancellationToken;

pub mod api;
pub mod metrics;
pub mod rp_registry;
pub mod services;

/// Returns cargo package name, cargo package version, and the git hash of the repository that was used to build the binary.
pub fn version_info() -> String {
    format!(
        "{} {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_HASH").unwrap_or(git_version::git_version!(fallback = "UNKNOWN"))
    )
}

/// Spawns a shutdown task and creates an associated [CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html). This task will complete when either the provided shutdown_signal futures completes or if some other tasks cancels the shutdown token. The associated shutdown token will be cancelled either way.
///
/// Waiting for the shutdown token is the preferred way to wait for termination.
pub fn spawn_shutdown_task(
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
    use std::sync::Arc;
    use std::{collections::HashMap, time::Duration};

    use ark_ff::UniformRand;
    use async_trait::async_trait;
    use axum::Router;
    use axum_test::TestServer;
    use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, DLogShareShamir};
    use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
    use oprf_types::crypto::{PartyId, RpNullifierKey};
    use oprf_types::{RpId, ShareEpoch};
    use rand::Rng as _;
    use uuid::Uuid;

    use crate::services::oprf::{OprfReqAuthenticator, OprfService};
    use crate::services::rp_material_store::{RpMaterial, RpMaterialStore};

    use super::*;

    struct TestOprfReqAuthenticator;

    #[async_trait]
    impl OprfReqAuthenticator for TestOprfReqAuthenticator {
        type ReqAuth = ();
        type ReqAuthError = ();

        async fn verify(
            &self,
            _req: &OprfRequest<Self::ReqAuth>,
        ) -> Result<(), Self::ReqAuthError> {
            Ok(())
        }
    }

    struct TestSetup {
        server: TestServer,
        oprf_service: OprfService,
        oprf_req: OprfRequest<()>,
        challenge_req: ChallengeRequest,
    }

    impl TestSetup {
        async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();

            let share_epoch = ShareEpoch::default();

            let rp_id = RpId::new(rng.r#gen());
            let rp_secret_key = k256::SecretKey::random(&mut rng);
            let rp_public_key = rp_secret_key.public_key();

            let request_id = Uuid::new_v4();
            let action = ark_babyjubjub::Fq::rand(&mut rng);
            let mt_index = rng.gen_range(0..(1 << 30)) as u64;
            let query_hash = oprf_core::oprf::client::generate_query(
                mt_index.into(),
                rp_id.into_inner().into(),
                action,
            );
            let (blinded_request, _blinding_factor) =
                oprf_core::oprf::client::blind_query(query_hash, &mut rng);
            let oprf_req = OprfRequest {
                request_id,
                blinded_query: blinded_request.blinded_query(),
                rp_identifier: NullifierShareIdentifier { rp_id, share_epoch },
                auth: (),
            };
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

            let request_lifetime = Duration::from_secs(5 * 60);
            let session_cleanup_interval = Duration::from_secs(30);
            let oprf_service = OprfService::init(
                rp_material,
                request_lifetime,
                session_cleanup_interval,
                PartyId(0),
            );
            let routes = Router::new().nest(
                "/api/v1",
                api::v1::routes(oprf_service.clone(), Arc::new(TestOprfReqAuthenticator)),
            );
            let server = TestServer::builder()
                .expect_success_by_default()
                .mock_transport()
                .build(routes)
                .unwrap();

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
        res.assert_text(format!("cannot find RP with id: {unknown_rp_id}"));
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
            "cannot find share with epoch {unknown_share_epoch}",
        ));
        res.assert_status_not_found();
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
            "cannot find share with epoch {unknown_share_epoch}",
        ));
        res.assert_status_not_found();
        Ok(())
    }
}
