#![deny(missing_docs, clippy::unwrap_used)]
//! This crate provides utility functions for clients of the distributed OPRF protocol.
//!
//! Most implementations will only need the [`distributed_oprf`] method. For more fine-grained workflows, we expose all necessary functions.
use ark_ec::AffineRepr as _;
use oprf_core::{
    ddlog_equality::shamir::DLogCommitmentsShamir,
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfRequest, BlindedOprfResponse},
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, ShareIdentifier},
    crypto::OprfPublicKey,
};
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use tracing::instrument;
use uuid::Uuid;

mod sessions;
pub use sessions::OprfSessions;
pub use sessions::finish_sessions;
pub use sessions::init_sessions;

/// Errors returned by the distributed OPRF protocol.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// API error returned by the OPRF service.
    #[error("API error {status}: {message}")]
    ApiError {
        /// the HTTP status code
        status: StatusCode,
        /// the error message
        message: String,
    },
    /// HTTP or network errors from OPRF service requests.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    /// Not enough OPRF responses received to satisfy the required threshold.
    #[error("expected degree {threshold} responses, got {n}")]
    NotEnoughOprfResponses {
        /// actual amount responses
        n: usize,
        /// expected threshold
        threshold: usize,
    },
    /// The DLog equality proof failed verification.
    #[error("DLog proof could not be verified")]
    InvalidDLogProof,
}

/// The result of the distributed OPRF protocol.
#[derive(Debug, Clone)]
pub struct VerifiableOprfOutput {
    /// The generated OPRF output.
    pub output: ark_babyjubjub::Fq,
    /// The DLog equality proof.
    pub dlog_proof: DLogEqualityProof,
    /// The blinded OPRF response.
    pub blinded_response: ark_babyjubjub::EdwardsAffine,
    /// The unblinded OPRF response.
    pub unblinded_response: ark_babyjubjub::EdwardsAffine,
}

/// Executes the distributed OPRF protocol.
///
/// This function performs the full client-side workflow of the distributed OPRF protocol:
/// 1. Blinds the input query using the provided blinding factor.
/// 2. Initializes sessions with the specified OPRF services, sending the blinded query and authentication information.
/// 3. Generates the DLog equality challenge based on the commitments received from the services.
/// 4. Finishes the sessions by sending the challenge to the services and collecting their responses
/// 5. Verifies the combined DLog equality proof from the services.
/// 6. Unblinds the combined OPRF response using the blinding factor.
/// 7. Computes the final OPRF output by hashing the original query and the unblinded response.
///
/// # Returns
/// The final [`VerifiableOprfOutput`] containing the OPRF output, the DLog equality proof, the blinded and unblinded responses.
///
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = tracing::field::Empty))]
#[expect(clippy::too_many_arguments)]
pub async fn distributed_oprf<T>(
    services: &[String],
    threshold: usize,
    oprf_public_key: OprfPublicKey,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    query: ark_babyjubjub::Fq,
    blinding_factor: ark_babyjubjub::Fr,
    auth: T,
) -> Result<VerifiableOprfOutput, Error>
where
    T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let request_id = Uuid::new_v4();
    let distributed_oprf_span = tracing::Span::current();
    distributed_oprf_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let share_identifier = ShareIdentifier {
        oprf_key_id,
        share_epoch,
    };

    let (blinded_request, blinding_factor) =
        oprf_core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        share_identifier,
        auth,
    };

    tracing::debug!("initializing sessions at {} services", services.len());
    let reqwest_client = reqwest::Client::new();
    let sessions = sessions::init_sessions(&reqwest_client, services, threshold, oprf_req).await?;

    tracing::debug!("compute the challenges for the services..");
    let challenge_request = generate_challenge_request(request_id, share_identifier, &sessions);
    // Extract the DLog challenge for later use
    let challenge = challenge_request.challenge.clone();

    tracing::debug!("finishing the sessions at the remaining services..");
    let responses = sessions::finish_sessions(&reqwest_client, sessions, challenge_request).await?;

    let dlog_proof = verify_dlog_equality(
        request_id,
        oprf_public_key,
        &blinded_request,
        responses,
        challenge.clone(),
    )?;

    let blinded_response = challenge.blinded_response();
    let blinding_factor_prepared = blinding_factor.clone().prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

    let digest = poseidon2::bn254::t4::permutation(&[
        oprf_core::oprf::client::get_oprf_ds(),
        query,
        unblinded_response.x,
        unblinded_response.y,
    ]);

    let output = digest[1];

    Ok(VerifiableOprfOutput {
        output,
        blinded_response,
        dlog_proof,
        unblinded_response,
    })
}

/// Combines the [`ChallengeResponse`]s of the OPRF nodes and computes the final [`DLogEqualityProof`].
///
/// Verifies the proof and returns an [`Error`] iff the proof is invalid.
#[instrument(level = "debug", skip_all, fields(request_id = %request_id))]
pub fn verify_dlog_equality(
    request_id: Uuid,
    oprf_public_key: OprfPublicKey,
    blinded_request: &BlindedOprfRequest,
    responses: Vec<ChallengeResponse>,
    challenge: DLogCommitmentsShamir,
) -> Result<DLogEqualityProof, Error> {
    let proofs = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();
    let party_ids = challenge.get_contributing_parties().to_vec();
    let blinded_response = challenge.blinded_response();
    let dlog_proof = challenge.combine_proofs(
        request_id,
        &party_ids,
        &proofs,
        oprf_public_key.inner(),
        blinded_request.blinded_query(),
    );
    dlog_proof
        .verify(
            oprf_public_key.inner(),
            blinded_request.blinded_query(),
            blinded_response,
            ark_babyjubjub::EdwardsAffine::generator(),
        )
        .map_err(|_| Error::InvalidDLogProof)?;
    Ok(dlog_proof)
}

/// Generates the [`ChallengeRequest`] for the OPRF nodes used for the second step of the distributed OPRF protocol, respecting the returned set of sessions.
#[instrument(level = "debug", skip(sessions))]
pub fn generate_challenge_request(
    request_id: Uuid,
    share_identifier: ShareIdentifier,
    sessions: &OprfSessions,
) -> ChallengeRequest {
    let contributing_parties = sessions
        .party_ids
        .iter()
        .map(|id| id.into_inner() + 1)
        .collect::<Vec<_>>();
    // Combine commitments from all sessions and create a single challenge
    let challenge =
        DLogCommitmentsShamir::combine_commitments(&sessions.commitments, contributing_parties);
    ChallengeRequest {
        request_id,
        challenge,
        share_identifier,
    }
}
