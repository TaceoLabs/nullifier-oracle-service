//! OPRF service for session initialization and client proof verification.
//!
//! Responsibilities:
//! - Verify client Groth16 proofs over the provided BabyJubJub point
//! - Produce partial discrete-log equality commitments via the [`CryptoDevice`]
//! - Persist per-session randomness in the [`SessionStore`]
use std::{fmt, sync::Arc};

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use eyre::Context;
use oprf_core::{
    ark_serde_compat::{self, groth16::Groth16Proof},
    ddlog_equality::{
        DLogEqualityChallenge, DLogEqualityProofShare, PartialDLogEqualityCommitments,
    },
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    config::OprfConfig,
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{
        chain_watcher::MerkleEpoch, crypto_device::CryptoDevice, session_store::SessionStore,
    },
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfServiceError {
    #[error("client proof did not verify")]
    InvalidProof,
    #[error("unknown request id: {0}")]
    UnknownRequestId(Uuid),
    #[error(transparent)]
    InternalServerErrpr(#[from] eyre::Report),
}

#[derive(Deserialize)]
pub struct OprfRequest {
    pub request_id: Uuid,
    pub user_proof: Groth16Proof,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_affine")]
    pub point_a: ark_babyjubjub::EdwardsAffine,
    pub epoch: MerkleEpoch,
}

#[derive(Debug, Serialize)]
pub struct OprfResponse {
    pub request_id: Uuid,
    pub commitments: PartialDLogEqualityCommitments,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub request_id: Uuid,
    pub challenge: DLogEqualityChallenge,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub request_id: Uuid,
    pub proof_share: DLogEqualityProofShare,
}

impl fmt::Debug for OprfRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfRequest")
            .field("req_id", &self.request_id)
            .field("A", &self.point_a.to_string())
            .field("proof", &"omitted")
            .finish()
    }
}

impl fmt::Debug for ChallengeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeRequest")
            .field("req_id", &self.request_id)
            .field("challenge", &"omitted")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct OprfService {
    crypto_device: Arc<CryptoDevice>,
    session_store: SessionStore,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

impl OprfService {
    /// Builds an `OprfService` from configuration, the device's secret share, and a Groth16 verifying key.
    pub(crate) fn init(
        config: Arc<OprfConfig>,
        crypto_device: CryptoDevice,
        vk: ark_groth16::VerifyingKey<Bn254>,
    ) -> Self {
        Self {
            crypto_device: Arc::new(crypto_device),
            session_store: SessionStore::init(config),
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk)),
        }
    }

    /// Initializes the OPRF session identified by the provided `Uuid`.
    ///
    /// The method verifies the provided user proof. Only if the ZK proof verification succeeds, the service executes [`CryptoDevice::partial_commit`], stores the generated randomness in the [`SessionStore`], and finally returns the Base64 encoded [`PartialDLogEqualityCommitments`] in compressed form.
    ///
    /// This method only fails if the provided ZK proof does not verify, in which case it returns an [`OprfServiceError`].
    #[instrument(level = "debug", skip(self))]
    pub(crate) fn init_oprf_session(
        &self,
        request: OprfRequest,
    ) -> Result<PartialDLogEqualityCommitments, OprfServiceError> {
        tracing::debug!("handling session request: {}", request.request_id);
        // Verify the user proof
        self.verify_user_proof(request.user_proof, request.point_a)?;
        // Partial commit through the crypto device
        let (session, comm) = self.crypto_device.partial_commit(request.point_a);
        // Store the randomness for finalize request
        self.session_store.store(request.request_id, session);
        tracing::debug!("handled session");
        Ok(comm)
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) fn finalize_oprf_session(
        &self,
        request: ChallengeRequest,
    ) -> Result<DLogEqualityProofShare, OprfServiceError> {
        tracing::debug!("handling challenge request: {}", request.request_id);
        // Retrieve the randomness from the previous step. If the request is not known, we return an error
        let session = self
            .session_store
            .retrieve(request.request_id)
            .ok_or_else(|| OprfServiceError::UnknownRequestId(request.request_id))?;
        // Consume the randomness, produce the final proof share
        let proof_share = self.crypto_device.challenge(session, request.challenge);
        metrics::counter!(METRICS_KEY_OPRF_SUCCESS).increment(1);
        tracing::debug!("finished challenge");
        Ok(proof_share)
    }

    /// Verifies the client's Groth16 proof against the provided BabyJubJub point.
    #[instrument(level = "debug", skip_all)]
    fn verify_user_proof(
        &self,
        proof: Groth16Proof,
        input: ark_babyjubjub::EdwardsAffine,
    ) -> Result<(), OprfServiceError> {
        let valid = Groth16::<Bn254>::verify_proof(&self.vk, &proof.into(), &[input.x, input.y])
            .context("while verifying user proof")?;
        if valid {
            tracing::debug!("proof valid");
            Ok(())
        } else {
            tracing::debug!("proof INVALID");
            Err(OprfServiceError::InvalidProof)
        }
    }
}
