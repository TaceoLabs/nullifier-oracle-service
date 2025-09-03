//! OPRF service for session initialization and client proof verification.
//!
//! Responsibilities:
//! - Verify client Groth16 proofs over the provided BabyJubJub point
//! - Produce partial discrete-log equality commitments via the [`CryptoDevice`]
//! - Persist per-session randomness in the [`SessionStore`]
use std::sync::Arc;

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serde_compat::groth16::Groth16Proof;
use eyre::Context;
use oprf_core::ddlog_equality::{DLogEqualityProofShare, PartialDLogEqualityCommitments};
use oprf_types::api::v1::{ChallengeRequest, KeyIdentifier, OprfRequest};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    config::OprfConfig,
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{crypto_device::CryptoDevice, session_store::SessionStore},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfServiceError {
    #[error("client proof did not verify")]
    InvalidProof,
    #[error("unknown request id: {0}")]
    UnknownRequestId(Uuid),
    #[error("Cannot find share for Rp with epoch: {0:?}")]
    UnknownRpKeyEpoch(KeyIdentifier),
    #[error(transparent)]
    InternalServerErrpr(#[from] eyre::Report),
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
        let public = [
            request.point_b.x,
            request.point_b.y,
            request.merkle_root,
            request.rp_key_id.rp_id.into(),
            request.action,
            request.nonce,
        ];
        self.verify_user_proof(request.proof, &public)?;
        // Partial commit through the crypto device
        let (session, comm) = self
            .crypto_device
            .partial_commit(request.point_b, &request.rp_key_id)
            .ok_or_else(|| OprfServiceError::UnknownRpKeyEpoch(request.rp_key_id))?;
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
        let proof_share = self
            .crypto_device
            .challenge(session, request.challenge, &request.rp_key_id)
            .ok_or_else(|| OprfServiceError::UnknownRpKeyEpoch(request.rp_key_id))?;
        metrics::counter!(METRICS_KEY_OPRF_SUCCESS).increment(1);
        tracing::debug!("finished challenge");
        Ok(proof_share)
    }

    /// Verifies the client's Groth16 proof against the provided BabyJubJub point.
    #[instrument(level = "debug", skip_all)]
    fn verify_user_proof(
        &self,
        proof: Groth16Proof,
        public: &[ark_babyjubjub::Fq],
    ) -> Result<(), OprfServiceError> {
        let valid = Groth16::<Bn254>::verify_proof(&self.vk, &proof.into(), public)
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
