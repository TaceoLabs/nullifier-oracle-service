#![deny(missing_docs, clippy::unwrap_used)]
//! This crate provides utility functions for clients of the distributed OPRF protocol.
//!
//! Most implementations will only need the [`distributed_oprf`] method. For more fine-grained workflows, we expose all necessary functions.
use ark_ec::AffineRepr as _;
use oprf_core::{
    ddlog_equality::shamir::DLogCommitmentsShamir, dlog_equality::DLogEqualityProof,
    oprf::BlindedOprfRequest,
};
use oprf_types::{
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

/// Executes the distributed OPRF protocol.
///
/// This part is agnostic to the concrete use-case and serves as a helper function for instantiations of the protocol. The method expects an [`OprfRequest`] with an `Auth` part that will be evaluated at the OPRF peers.
///
/// This method tries to initialize a session at each endpoint provided in `services`. It stops as soon as it receives `threshold` answers, the other connections are dropped (the servers are expected to handle that gracefully).
///
/// We then prepare challenges for the remaining peers and with their answers we compute the final [`DLogEqualityProof`].
///
/// Most implementations of TACEO:Oprf will only need this function. In case you want more fine-grained control, you can use the other exposed functions in this module.
///
/// # Returns
/// The final [`DLogEqualityProof`] along with the created [`DLogCommitmentsShamir`].
///
/// # Errors
/// See the [`Error`] enum for all potential errors of this function.
#[instrument(level = "debug", skip_all, fields(request_id = %request_id))]
pub async fn distributed_oprf<Auth>(
    request_id: Uuid,
    oprf_public_key: OprfPublicKey,
    services: &[String],
    threshold: usize,
    req: OprfRequest<Auth>,
    blinded_request: &BlindedOprfRequest,
) -> Result<(DLogCommitmentsShamir, DLogEqualityProof), Error>
where
    Auth: Send + Sync + Clone + Serialize + DeserializeOwned + 'static,
{
    let share_identifier = req.share_identifier;
    // Init the sessions at the services
    tracing::debug!("initializing sessions at {} services", services.len());
    let reqwest_client = reqwest::Client::new();
    let sessions = sessions::init_sessions(&reqwest_client, services, threshold, req).await?;

    tracing::debug!("compute the challenges for the services..");
    let challenge_request = generate_challenge_request(request_id, share_identifier, &sessions);
    // Extract the DLog challenge for later use
    let challenge = challenge_request.challenge.clone();

    tracing::debug!("finishing the sessions at the remaining services..");
    let responses = sessions::finish_sessions(&reqwest_client, sessions, challenge_request).await?;

    // verify the DLog Equality Proof
    let dlog_proof = verify_dlog_equality(
        request_id,
        oprf_public_key,
        blinded_request,
        responses,
        challenge.clone(),
    )?;
    Ok((challenge, dlog_proof))
}

/// Combines the [`ChallengeResponse`]s of the OPRF peers and computes the final [`DLogEqualityProof`].
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

/// Generates the [`ChallengeRequest`] for the OPRF peers used for the second step of the distributed OPRF protocol, respecting the returned set of sessions.
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
