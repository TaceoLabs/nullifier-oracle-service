use ark_ec::AffineRepr as _;
use oprf_core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, PartialDLogCommitmentsShamir},
    dlog_equality::DLogEqualityProof,
    oprf::BlindedOprfRequest,
};
use oprf_types::{
    api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse, ShareIdentifier},
    crypto::{OprfPublicKey, PartyId},
};
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use tracing::instrument;
use uuid::Uuid;

pub mod nonblocking;

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

/// Holds information about active OPRF sessions with multiple peers.
///
/// Tracks the peer services, their party IDs, and the partial DLog equality
/// commitments received from each peer.
pub struct OprfSessions {
    services: Vec<String>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogCommitmentsShamir>,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    fn with_capacity(capacity: usize) -> Self {
        Self {
            services: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
        }
    }

    /// Adds a peer's response to the sessions.
    fn push(&mut self, service: String, response: OprfResponse) {
        self.services.push(service);
        self.party_ids.push(response.party_id);
        self.commitments.push(response.commitments);
    }

    /// Returns the number of sessions currently stored.
    fn len(&self) -> usize {
        self.services.len()
    }
}

#[instrument(
    level = "debug",
    skip(oprf_public_key, services, threshold, req, blinded_request)
)]
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
    let sessions = nonblocking::init_sessions(&reqwest_client, services, threshold, req).await?;

    tracing::debug!("compute the challenges for the services..");
    let challenge_request = generate_challenge_request(request_id, share_identifier, &sessions);
    // Extract the DLog challenge for later use
    let challenge = challenge_request.challenge.clone();

    tracing::debug!("finishing the sessions at the remaining services..");
    let responses =
        nonblocking::finish_sessions(&reqwest_client, sessions, challenge_request).await?;

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

#[instrument(
    level = "debug",
    skip(oprf_public_key, blinded_request, responses, challenge)
)]
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
