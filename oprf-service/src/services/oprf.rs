//! Provides functionality for OPRF session management.
//!
//! Responsibilities:
//! - Produce partial discrete-log equality commitments via the [`RpMaterialStore`].
//! - Persist per-session randomness in the [`SessionStore`] for later challenge completion.
//!
//! The service exposes two main flows:
//! 1. [`OprfService::init_oprf_session`] – initializes an OPRF session, computes partial commitments, and stores the session randomness.
//! 2. [`OprfService::finalize_oprf_session`] – consumes the stored randomness to produce a final proof share for the client challenge.
//!
//! This service is designed to be used behind an HTTP API (via the `api` module).
//!
//! We refer to [Section 3 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-protocol.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use oprf_core::ddlog_equality::shamir::{DLogProofShareShamir, PartialDLogCommitmentsShamir};
use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
use oprf_types::crypto::PartyId;
use serde::{Serialize, de::DeserializeOwned};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    metrics::METRICS_KEY_OPRF_SUCCESS,
    services::{
        rp_material_store::{RpMaterialStore, RpMaterialStoreError},
        session_store::SessionStore,
    },
};

/// Errors returned by the [`OprfService`].
#[derive(Debug, thiserror::Error)]
pub enum OprfServiceError {
    /// The blinded query is the identity element
    #[error("blinded query input is the identity element - not allowed")]
    BlindedQueryIsIdentity,
    /// The request ID is unknown or has already been finalized.
    #[error("unknown request id: {0}")]
    UnknownRequestId(Uuid),
    /// Error from RpMaterialStore
    #[error(transparent)]
    RpMaterialStoreError(#[from] RpMaterialStoreError),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

#[async_trait]
pub trait OprfReqAuthenticator: Send + Sync {
    type ReqAuth: Clone + Serialize + DeserializeOwned;
    type ReqAuthError: axum::response::IntoResponse;

    async fn verify(&self, req: &OprfRequest<Self::ReqAuth>) -> Result<(), Self::ReqAuthError>;
}

pub type OprfReqAuthService<ReqAuth, ReqAuthError> =
    Arc<dyn OprfReqAuthenticator<ReqAuth = ReqAuth, ReqAuthError = ReqAuthError>>;

/// Main OPRF service managing session lifecycle and cryptographic operations.
///
/// Holds references to the RP material store, session store, merkle watcher,
/// signature history, and verification key. Cloneable for use across multiple
/// tasks and API handlers.
#[derive(Clone)]
pub struct OprfService {
    pub(crate) rp_material_store: RpMaterialStore,
    pub(crate) session_store: SessionStore,
    pub(crate) party_id: PartyId,
}

impl OprfService {
    /// Builds an [`OprfService`] from its core services and config values.
    pub fn init(
        rp_material_store: RpMaterialStore,
        request_lifetime: Duration,
        session_cleanup_interval: Duration,
        party_id: PartyId,
    ) -> Self {
        Self {
            rp_material_store,
            session_store: SessionStore::init(session_cleanup_interval, request_lifetime),
            party_id,
        }
    }

    /// Initializes an OPRF session for the given request.
    ///
    /// This method executes the first step of the OPRF protocol:
    /// - Computes partial discrete-log equality commitments using the [`RpMaterialStore`].
    /// - Stores the generated session randomness in the [`SessionStore`] for use during the challenge/finalization phase.
    #[instrument(level = "debug", skip_all, fields(request_id = %request_id))]
    pub(crate) async fn init_oprf_session(
        &self,
        request_id: Uuid,
        rp_identifier: NullifierShareIdentifier,
        blinded_query: ark_babyjubjub::EdwardsAffine,
    ) -> Result<PartialDLogCommitmentsShamir, OprfServiceError> {
        tracing::debug!("handling session request: {request_id}");

        // check that blinded query (B) is not the identity element
        if blinded_query.is_zero() {
            return Err(OprfServiceError::BlindedQueryIsIdentity);
        }

        // Partial commit through the crypto device
        let (session, comm) = self
            .rp_material_store
            .partial_commit(blinded_query, &rp_identifier)?;

        // Store the randomness for finalize request
        self.session_store.insert(request_id, session);
        tracing::debug!("handled session init");
        Ok(comm)
    }

    /// Finalizes an OPRF session for a client challenge request.
    ///
    /// - Retrieves the stored randomness from [`SessionStore`].
    /// - Computes the final discrete-log equality proof share using [`RpMaterialStore`].
    #[instrument(level = "debug", skip_all, fields(request_id = %request.request_id))]
    pub(crate) fn finalize_oprf_session(
        &self,
        request: ChallengeRequest,
    ) -> Result<DLogProofShareShamir, OprfServiceError> {
        tracing::debug!("handling challenge request: {}", request.request_id);
        // Retrieve the randomness from the previous step. If the request is not known, we return an error
        let session = self
            .session_store
            .remove(request.request_id)
            .ok_or_else(|| OprfServiceError::UnknownRequestId(request.request_id))?;
        // Consume the randomness, produce the final proof share
        let proof_share = self.rp_material_store.challenge(
            request.request_id,
            self.party_id,
            session,
            request.challenge,
            &request.rp_identifier,
        )?;
        metrics::counter!(METRICS_KEY_OPRF_SUCCESS).increment(1);
        tracing::debug!("finished challenge");
        Ok(proof_share)
    }
}
