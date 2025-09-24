//! # OPRF Service
//!
//! Provides functionality for OPRF session management.
//!
//! Responsibilities:
//! - Verify client Groth16 proofs and signature verification on session init.
//! - Produce partial discrete-log equality commitments via the [`CryptoDevice`].
//! - Persist per-session randomness in the [`SessionStore`] for later challenge completion.
//!
//! The service exposes two main flows:
//! 1. [`OprfService::init_oprf_session`] – initializes an OPRF session, verifies the user's proof, computes partial commitments, and stores the session randomness.
//! 2. [`OprfService::finalize_oprf_session`] – consumes the stored randomness to produce a final proof share for the client challenge.
//!
//! This service is designed to be used behind an HTTP API (via the `api` module).
//!
//! We refer to [Section 3 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-protocol.

use std::sync::Arc;

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serde_compat::groth16::Groth16Proof;
use eyre::Context;
use oprf_core::ddlog_equality::{DLogEqualityProofShare, PartialDLogEqualityCommitments};
use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    config::OprfPeerConfig,
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{
        chain_watcher::{ChainWatcherError, ChainWatcherService},
        crypto_device::CryptoDevice,
        session_store::SessionStore,
    },
};

/// Errors returned by the [`OprfService`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfServiceError {
    /// The client Groth16 proof did not verify.
    #[error("client proof did not verify")]
    InvalidProof,
    /// The request ID is unknown or has already been finalized.
    #[error("unknown request id: {0}")]
    UnknownRequestId(Uuid),
    /// Cannot find a secret share for the given RP at the requested epoch.
    #[error("Cannot find share for Rp with epoch: {0:?}")]
    UnknownRpShareEpoch(NullifierShareIdentifier),
    /// An error returned from the chain watcher service during merkle look-up.
    #[error(transparent)]
    ChainWatcherError(#[from] ChainWatcherError),
    /// Internal server error
    #[error(transparent)]
    InternalServerErrpr(#[from] eyre::Report),
}

#[derive(Clone)]
pub(crate) struct OprfService {
    crypto_device: Arc<CryptoDevice>,
    session_store: SessionStore,
    chain_watcher: ChainWatcherService,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

impl OprfService {
    /// Builds an [`OprfService`] from configuration, a [`CryptoDevice`], a [`ChainWatcherService`], and a Groth16 verifying key for the client proof.
    pub(crate) fn init(
        config: Arc<OprfPeerConfig>,
        crypto_device: Arc<CryptoDevice>,
        chain_watcher: ChainWatcherService,
        vk: ark_groth16::VerifyingKey<Bn254>,
    ) -> Self {
        Self {
            crypto_device,
            session_store: SessionStore::init(config),
            chain_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk)),
        }
    }

    /// Initializes an OPRF session for the given request.
    ///
    /// This method executes the first step of the OPRF protocol:
    /// 1. Retrieves the Merkle root for the epoch specified in the request via the [`ChainWatcherService`].
    /// 2. Verifies the client's Groth16 proof.
    /// 3. If verification succeeds, computes partial discrete-log equality commitments using the [`CryptoDevice`].
    /// 4. Stores the generated session randomness in the [`SessionStore`] for use during the challenge/finalization phase.
    ///
    /// Returns the compressed Base64-encoded [`PartialDLogEqualityCommitments`] if successful.
    ///
    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn init_oprf_session(
        &self,
        request: OprfRequest,
    ) -> Result<PartialDLogEqualityCommitments, OprfServiceError> {
        tracing::debug!("handling session request: {}", request.request_id);

        // get the merkle root identified by the epoch
        let merkle_root = self
            .chain_watcher
            .get_merkle_root_by_epoch(request.merkle_epoch)
            .await?;

        // Verify the user proof
        let public = [
            request.point_b.x,
            request.point_b.y,
            merkle_root.into_inner(),
            request.rp_key_id.rp_id.into(),
            request.action,
            request.nonce,
        ];
        self.verify_user_proof(request.proof, &public)?;
        // Partial commit through the crypto device
        let (session, comm) = self
            .crypto_device
            .partial_commit(request.point_b, &request.rp_key_id)
            .ok_or_else(|| OprfServiceError::UnknownRpShareEpoch(request.rp_key_id))?;
        // Store the randomness for finalize request
        self.session_store.store(request.request_id, session);
        tracing::debug!("handled session init");
        Ok(comm)
    }

    /// Finalizes an OPRF session for a client challenge request.
    ///
    /// - Retrieves the stored randomness from [`SessionStore`].
    /// - Computes the final discrete-log equality proof share using [`CryptoDevice`].
    /// - Returns the proof share or an error if the session or share cannot be found.
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
            .challenge(session, request.challenge, &request.rp_nullifier_share_id)
            .ok_or_else(|| OprfServiceError::UnknownRpShareEpoch(request.rp_nullifier_share_id))?;
        metrics::counter!(METRICS_KEY_OPRF_SUCCESS).increment(1);
        tracing::debug!("finished challenge");
        Ok(proof_share)
    }

    /// Verifies a client's Groth16 proof against the provided public inputs.
    ///
    /// Returns [`OprfServiceError::InvalidProof`] if verification fails.
    #[instrument(level = "debug", skip_all)]
    fn verify_user_proof(
        &self,
        proof: Groth16Proof,
        public: &[ark_babyjubjub::Fq],
    ) -> Result<(), OprfServiceError> {
        tracing::debug!("verifying user proof...");
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
