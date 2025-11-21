use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use ark_bn254::Bn254;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use oprf_service::services::oprf::OprfReqAuthenticator;
use oprf_types::api::v1::OprfRequest;
use oprf_world_types::{TREE_DEPTH, api::v1::OprfRequestAuth};
use uuid::Uuid;

use crate::services::{
    merkle_watcher::{MerkleWatcherError, MerkleWatcherService},
    signature_history::{DuplicateSignatureError, SignatureHistory},
};

/// Errors returned by the [`WorldOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum WorldOprfReqAuthError {
    /// The client Groth16 proof did not verify.
    #[error("client proof did not verify")]
    InvalidProof,
    /// An error returned from the merkle watcher service during merkle look-up.
    #[error(transparent)]
    MerkleWatcherError(#[from] MerkleWatcherError),
    /// The current time stamp difference between client and service is larger than allowed.
    #[error("the time stamp difference is too large")]
    TimeStampDifference,
    /// A nonce signature was uses more than once
    #[error(transparent)]
    DuplicateSignatureError(#[from] DuplicateSignatureError),
    /// The provided merkle root is not valid
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for WorldOprfReqAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            WorldOprfReqAuthError::InvalidProof => {
                (StatusCode::BAD_REQUEST, "invalid proof").into_response()
            }
            WorldOprfReqAuthError::MerkleWatcherError(err) => {
                tracing::error!("merkle watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            WorldOprfReqAuthError::TimeStampDifference => (
                StatusCode::BAD_REQUEST,
                "the time stamp difference is too large",
            )
                .into_response(),
            WorldOprfReqAuthError::DuplicateSignatureError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            WorldOprfReqAuthError::InvalidMerkleRoot => {
                (StatusCode::BAD_REQUEST, "invalid merkle root").into_response()
            }
            WorldOprfReqAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

pub(crate) struct WorldOprfReqAuthenticator {
    merkle_watcher: MerkleWatcherService,
    signature_history: SignatureHistory,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
    current_time_stamp_max_difference: Duration,
}

impl WorldOprfReqAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcherService,
        vk: ark_groth16::VerifyingKey<Bn254>,
        current_time_stamp_max_difference: Duration,
        signature_history_cleanup_interval: Duration,
    ) -> Self {
        Self {
            signature_history: SignatureHistory::init(
                current_time_stamp_max_difference * 2,
                signature_history_cleanup_interval,
            ),
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk)),
            current_time_stamp_max_difference,
        }
    }
}

#[async_trait]
impl OprfReqAuthenticator for WorldOprfReqAuthenticator {
    type ReqAuth = OprfRequestAuth;
    type ReqAuthError = WorldOprfReqAuthError;

    async fn verify(&self, request: &OprfRequest<Self::ReqAuth>) -> Result<(), Self::ReqAuthError> {
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(WorldOprfReqAuthError::TimeStampDifference);
        }

        // TODO
        // check the RP nonce signature - this also lightens the threat
        // of DoS attack that force the service to always check the merkle roots from chain
        // self.rp_material_store.verify_nonce_signature(
        //     rp_id,
        //     request.auth.nonce,
        //     request.auth.current_time_stamp,
        //     &request.auth.signature,
        // )?;

        // add signature to history to check if the nonces where only used once
        self.signature_history
            .add_signature(request.auth.signature.to_vec(), req_time_stamp)
            .unwrap();

        // check if the merkle root is valid
        let valid = self
            .merkle_watcher
            .is_root_valid(request.auth.merkle_root)
            .await
            .unwrap();
        if !valid {
            return Err(WorldOprfReqAuthError::InvalidMerkleRoot)?;
        }

        // verify the user proof
        let public = [
            request.blinded_query.x,
            request.blinded_query.y,
            request.auth.cred_pk.pk.x,
            request.auth.cred_pk.pk.y,
            request.auth.current_time_stamp.into(),
            request.auth.merkle_root.into_inner(),
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            request.rp_identifier.rp_id.into(),
            request.auth.action,
            request.auth.nonce,
        ];

        tracing::debug!("verifying user proof...");
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(
            &self.vk,
            &request.auth.proof.clone().into(),
            &public,
        )
        .unwrap();
        if valid {
            tracing::debug!("proof valid");
            Ok(())
        } else {
            tracing::debug!("proof INVALID");
            Err(WorldOprfReqAuthError::InvalidProof)
        }
    }
}
