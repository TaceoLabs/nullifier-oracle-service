//! OPRF service for session initialization and client proof verification.
//!
//! Responsibilities:
//! - Verify client Groth16 proofs over the provided BabyJubJub point
//! - Produce partial discrete-log equality commitments via the [`CryptoDevice`]
//! - Persist per-session randomness in the [`SessionStore`]
use std::fmt;
use std::sync::Arc;

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use base64ct::{Base64, Encoding};
use eyre::Context;
use oprf_core::ddlog_equality::DLogEqualityChallenge;
use tracing::instrument;
use uuid::Uuid;

type Groth16Proof = ark_groth16::Proof<Bn254>;

use crate::{
    api::v1::oprf::{ChallengeRequest, OprfRequest},
    config::OprfConfig,
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{crypto_device::CryptoDevice, session_store::SessionStore},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfServiceError {
    #[error("client proof did not verify")]
    InvalidProof,
    #[error(transparent)]
    MalformedBase64(#[from] base64ct::Error),
    #[error("malformed groth16 proof: {0}")]
    MalformedGrothProof(#[source] SerializationError),
    #[error("malformed BabyJubJub point: {0}")]
    MalformedPoint(#[source] SerializationError),
    #[error("malformed DLog Challenge: {0}")]
    MalformedDLogChallenge(#[source] SerializationError),
    #[error("unknown request id: {0}")]
    UnknownRequestId(Uuid),
    #[error(transparent)]
    InternalServerErrpr(#[from] eyre::Report),
}

#[derive(Clone)]
pub(crate) struct OprfService {
    crypto_device: Arc<CryptoDevice>,
    session_store: SessionStore,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

pub(crate) struct InitOprfSessionRequest {
    id: Uuid,
    user_proof: Groth16Proof,
    point_a: ark_babyjubjub::EdwardsAffine,
}

pub(crate) struct FinalizeOprfSessionRequestn {
    id: Uuid,
    challenge: DLogEqualityChallenge,
}

impl fmt::Debug for InitOprfSessionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitOprfSessionRequest")
            .field("req_id", &self.id)
            .field("A", &self.point_a.to_string())
            .field("proof", &"omitted")
            .finish()
    }
}

impl fmt::Debug for FinalizeOprfSessionRequestn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishOprfSessionRequest")
            .field("req_id", &self.id)
            .field("challenge", &"omitted")
            .finish()
    }
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
        request: InitOprfSessionRequest,
    ) -> Result<String, OprfServiceError> {
        tracing::debug!("handling session request: {}", request.id);
        // Verify the user proof
        self.verify_user_proof(&request.user_proof, request.point_a)?;
        // Partial commit through the crypto device
        let (session, comm) = self.crypto_device.partial_commit(request.point_a);
        // Store the randomness for finalize request
        self.session_store.store(request.id, session);
        // Serialize result to bytes
        let bytes = comm.into_bytes().context("while serializing commitments")?;
        tracing::debug!("handled session");
        Ok(Base64::encode_string(&bytes))
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) fn finalize_oprf_session(
        &self,
        request: FinalizeOprfSessionRequestn,
    ) -> Result<String, OprfServiceError> {
        tracing::debug!("handling challenge request: {}", request.id);
        // Retrieve the randomness from the previous step. If the request is not known, we return an error
        let session = self
            .session_store
            .retrieve(request.id)
            .ok_or_else(|| OprfServiceError::UnknownRequestId(request.id))?;
        // Consume the randomness, produce the final proof share and serialize to bytes
        let proof_share = self
            .crypto_device
            .challenge(session, request.challenge)
            .into_bytes()
            .context("while serializing proof share")?;
        metrics::counter!(METRICS_KEY_OPRF_SUCCESS).increment(1);
        tracing::debug!("finished challenge");
        Ok(Base64::encode_string(&proof_share))
    }

    /// Verifies the client's Groth16 proof against the provided BabyJubJub point.
    #[instrument(level = "debug", skip_all)]
    fn verify_user_proof(
        &self,
        proof: &Groth16Proof,
        input: ark_babyjubjub::EdwardsAffine,
    ) -> Result<(), OprfServiceError> {
        let valid = Groth16::<Bn254>::verify_proof(&self.vk, proof, &[input.x, input.y])
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

impl TryFrom<OprfRequest> for InitOprfSessionRequest {
    type Error = OprfServiceError;

    /// Decodes an [`OprfRequest`] into an `InitOprfSessionRequest` by base64-decoding and deserializing compressed arkworks encodings of the proof and point.
    fn try_from(value: OprfRequest) -> Result<Self, Self::Error> {
        let proof_bytes = Base64::decode_vec(&value.user_proof)?;
        let point_a_bytes = Base64::decode_vec(&value.point_a)?;

        let user_proof = Groth16Proof::deserialize_compressed(proof_bytes.as_slice())
            .map_err(OprfServiceError::MalformedGrothProof)?;
        let point_a =
            ark_babyjubjub::EdwardsAffine::deserialize_compressed(point_a_bytes.as_slice())
                .map_err(OprfServiceError::MalformedPoint)?;
        Ok(Self {
            id: value.request_id,
            user_proof,
            point_a,
        })
    }
}

impl TryFrom<ChallengeRequest> for FinalizeOprfSessionRequestn {
    type Error = OprfServiceError;

    /// Decodes an [`ChallengeRequest`] into an `FinishOprfSessionRequest` by base64-decoding and deserializing compressed arkworks encodings of the [`DLogEqualityChallenge`].
    fn try_from(value: ChallengeRequest) -> Result<Self, Self::Error> {
        let challenge_bytes = Base64::decode_vec(&value.challenge)?;
        let challenge = DLogEqualityChallenge::deserialize_compressed(challenge_bytes.as_slice())
            .map_err(OprfServiceError::MalformedDLogChallenge)?;
        Ok(Self {
            id: value.request_id,
            challenge,
        })
    }
}
