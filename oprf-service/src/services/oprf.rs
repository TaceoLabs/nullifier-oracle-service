//! Provides functionality for OPRF session management.
//!
//! Responsibilities:
//! - Verify client Groth16 proofs and signature verification on session init.
//! - Produce partial discrete-log equality commitments via the [`RpMaterialStore`].
//! - Persist per-session randomness in the [`SessionStore`] for later challenge completion.
//!
//! The service exposes two main flows:
//! 1. [`OprfService::init_oprf_session`] – initializes an OPRF session, verifies the user's proof and nonce signature, computes partial commitments, and stores the session randomness.
//! 2. [`OprfService::finalize_oprf_session`] – consumes the stored randomness to produce a final proof share for the client challenge.
//!
//! This service is designed to be used behind an HTTP API (via the `api` module).
//!
//! We refer to [Section 3 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-protocol.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use eyre::Context;
use oprf_core::ddlog_equality::{DLogEqualityProofShare, PartialDLogEqualityCommitments};
use oprf_types::api::v1::{ChallengeRequest, OprfRequest};
use oprf_types::crypto::PartyId;
use oprf_world_types::{TREE_DEPTH, api::v1::OprfRequestAuth};
use oprf_zk::groth16_serde::Groth16Proof;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{
        merkle_watcher::{MerkleWatcherError, MerkleWatcherService},
        rp_material_store::{RpMaterialStore, RpMaterialStoreError},
        session_store::SessionStore,
        signature_history::{DuplicateSignatureError, SignatureHistory},
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
    /// Error from RpMaterialStore
    #[error(transparent)]
    RpMaterialStoreError(#[from] RpMaterialStoreError),
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
    InternalServerErrpr(#[from] eyre::Report),
}

/// Main OPRF service managing session lifecycle and cryptographic operations.
///
/// Holds references to the RP material store, session store, merkle watcher,
/// signature history, and verification key. Cloneable for use across multiple
/// tasks and API handlers.
#[derive(Clone)]
pub(crate) struct OprfService {
    pub(crate) rp_material_store: RpMaterialStore,
    pub(crate) session_store: SessionStore,
    merkle_watcher: MerkleWatcherService,
    signature_history: SignatureHistory,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
    current_time_stamp_max_difference: Duration,
}

impl OprfService {
    /// Builds an [`OprfService`] from its core services and config values.
    pub(crate) fn init(
        rp_material_store: RpMaterialStore,
        merkle_watcher: MerkleWatcherService,
        vk: ark_groth16::VerifyingKey<Bn254>,
        request_lifetime: Duration,
        session_cleanup_interval: Duration,
        current_time_stamp_max_difference: Duration,
        signature_history_cleanup_interval: Duration,
    ) -> Self {
        Self {
            rp_material_store,
            signature_history: SignatureHistory::init(
                current_time_stamp_max_difference * 2,
                signature_history_cleanup_interval,
            ),
            session_store: SessionStore::init(session_cleanup_interval, request_lifetime),
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk)),
            current_time_stamp_max_difference,
        }
    }

    /// Initializes an OPRF session for the given request.
    ///
    /// This method executes the first step of the OPRF protocol:
    /// 1. Verifies the RP's nonce signature via the [`RpMaterialStore`]. **The nonce is converted to le_bytes representation for signature verification**.
    /// 2. Check the Merkle root for the epoch specified in the request via the [`MerkleWatcherService`].
    /// 3. Verifies the client's Groth16 proof.
    /// 4. If verification succeeds, computes partial discrete-log equality commitments using the [`RpMaterialStore`].
    /// 5. Stores the generated session randomness in the [`SessionStore`] for use during the challenge/finalization phase.
    ///
    /// Returns the compressed Base64-encoded [`PartialDLogEqualityCommitments`] if successful.
    #[instrument(level = "debug", skip_all, fields(request_id = %request.request_id))]
    pub(crate) async fn init_oprf_session(
        &self,
        request: OprfRequest<OprfRequestAuth>,
    ) -> Result<PartialDLogEqualityCommitments, OprfServiceError> {
        tracing::debug!("handling session request: {}", request.request_id);
        let rp_id = request.rp_identifier.rp_id;

        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(OprfServiceError::TimeStampDifference);
        }

        // check the RP nonce signature - this also lightens the threat
        // of DoS attack that force the service to always check the merkle roots from chain
        self.rp_material_store.verify_nonce_signature(
            rp_id,
            request.auth.nonce,
            request.auth.current_time_stamp,
            &request.auth.signature,
        )?;

        // add signature to history to check if the nonces where only used once
        self.signature_history
            .add_signature(request.auth.signature.to_vec(), req_time_stamp)?;

        // check if the merkle root is valid
        let valid = self
            .merkle_watcher
            .is_root_valid(request.auth.merkle_root)
            .await?;
        if !valid {
            return Err(OprfServiceError::InvalidMerkleRoot)?;
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
        self.verify_user_proof(request.auth.proof, &public)?;

        // Partial commit through the crypto device
        let (session, comm) = self
            .rp_material_store
            .partial_commit(request.blinded_query, &request.rp_identifier)?;

        // Store the randomness for finalize request
        self.session_store.insert(request.request_id, session);
        tracing::debug!("handled session init");
        Ok(comm)
    }

    /// Finalizes an OPRF session for a client challenge request.
    ///
    /// - Retrieves the stored randomness from [`SessionStore`].
    /// - Computes the final discrete-log equality proof share using [`RpMaterialStore`].
    /// - Returns the proof share or an error if the session or share cannot be found.
    #[instrument(level = "debug", skip_all, fields(request_id = %request.request_id))]
    pub(crate) fn finalize_oprf_session(
        &self,
        my_party_id: PartyId,
        request: ChallengeRequest,
    ) -> Result<DLogEqualityProofShare, OprfServiceError> {
        tracing::debug!("handling challenge request: {}", request.request_id);
        // Retrieve the randomness from the previous step. If the request is not known, we return an error
        let session = self
            .session_store
            .remove(request.request_id)
            .ok_or_else(|| OprfServiceError::UnknownRequestId(request.request_id))?;
        // Consume the randomness, produce the final proof share
        let proof_share = self.rp_material_store.challenge(
            request.request_id,
            my_party_id,
            session,
            request.challenge,
            &request.rp_identifier,
        )?;
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
