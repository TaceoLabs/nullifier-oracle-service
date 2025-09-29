//! API Error Handling
//!
//! This module defines the error types and conversions used by the OPRF peer API.
//!
//! - [`ApiError`] is a structured error returned to clients, including an optional
//!   message and an HTTP status code.
//! - [`ApiErrors`] is an enum representing different kinds of API errors internally,
//!   including authorization errors, resource-not-found errors, explicit errors, and
//!   internal server errors.
//!
//! Conversions are provided from service-level errors like [`OprfServiceError`] into
//! API errors, ensuring consistent HTTP responses.
//!
//! All errors implement [`IntoResponse`] so they can be directly returned from Axum
//! handlers.

use axum::{Json, http::StatusCode, response::IntoResponse};
use eyre::Report;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::services::{
    chain_watcher::ChainWatcherError, crypto_device::CryptoDeviceError, oprf::OprfServiceError,
};

/// A structured API error returned to clients.
#[derive(Debug, Serialize)]
pub(crate) struct ApiError {
    /// Optional human-readable message.
    pub(crate) message: Option<String>,
    /// HTTP status code for this error.
    #[serde(serialize_with = "serialize_status_code")]
    pub(crate) code: StatusCode,
}

impl IntoResponse for ApiError {
    /// Convert the API error into an Axum response.
    fn into_response(self) -> axum::response::Response {
        (self.code, Json(self)).into_response()
    }
}

/// Result type used by API endpoints.
pub(crate) type ApiResult<T> = Result<T, ApiErrors>;

/// Represents all possible API errors internally.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiErrors {
    #[error("an explicit error was returned: {0:?}")]
    ExplicitError(ApiError),
    #[error("Cannot find resource: \"{0}\"")]
    NotFound(String),
    #[error("Bad request: \"{0}\"")]
    BadRequest(String),
    #[error(transparent)]
    InternalSeverError(#[from] eyre::Report),
}

impl From<ApiError> for ApiErrors {
    fn from(inner: ApiError) -> Self {
        ApiErrors::ExplicitError(inner)
    }
}

impl From<ChainWatcherError> for ApiErrors {
    fn from(value: ChainWatcherError) -> Self {
        tracing::debug!("{value:?}");
        match value {
            ChainWatcherError::UnknownEpoch(epoch)
            | ChainWatcherError::TooFarInFuture(epoch)
            | ChainWatcherError::TooFarInPast(epoch) => {
                ApiErrors::BadRequest(format!("not known epoch: {epoch}"))
            }
            ChainWatcherError::ChainCommunicationError(report) => {
                ApiErrors::InternalSeverError(report)
            }
        }
    }
}

impl From<OprfServiceError> for ApiErrors {
    fn from(value: OprfServiceError) -> Self {
        tracing::debug!("{value:?}");
        match value {
            OprfServiceError::InvalidProof => ApiErrors::BadRequest("invalid proof".to_string()),
            OprfServiceError::UnknownRequestId(request) => ApiErrors::NotFound(request.to_string()),
            OprfServiceError::CryptoDevice(crypto_device_error) => Self::from(crypto_device_error),
            OprfServiceError::ChainWatcherError(chain_watcher_error) => {
                Self::from(chain_watcher_error)
            }
            OprfServiceError::InternalServerErrpr(report) => ApiErrors::InternalSeverError(report),
            OprfServiceError::TimeStampDifference => {
                ApiErrors::BadRequest("the time stamp difference is too large".to_string())
            }
            OprfServiceError::DuplicateSignatureError(err) => {
                ApiErrors::BadRequest(err.to_string())
            }
            OprfServiceError::MerkleDepthGreaterThanMax(max) => {
                ApiErrors::BadRequest(format!("merkle tree depth greater than max: {max}"))
            }
        }
    }
}

impl From<CryptoDeviceError> for ApiErrors {
    fn from(value: CryptoDeviceError) -> Self {
        match value {
            CryptoDeviceError::NoSuchRp(rp_id) => {
                ApiErrors::NotFound(format!("Cannot find RP with id: {rp_id}"))
            }
            CryptoDeviceError::NonceSignatureError(error) => {
                ApiErrors::BadRequest(format!("Invalid signature: {error}"))
            }
            CryptoDeviceError::UnknownRpShareEpoch(key_identifier) => ApiErrors::NotFound(format!(
                "Cannot find share for rp_id: {} , epoch: {}",
                key_identifier.rp_id, key_identifier.share_epoch
            )),
        }
    }
}

impl IntoResponse for ApiErrors {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiErrors::ExplicitError(ApiError { message, code }) => {
                (code, message.unwrap_or(String::from("unknown error"))).into_response()
            }
            ApiErrors::InternalSeverError(inner) => {
                handle_internal_server_error(inner).into_response()
            }
            ApiErrors::NotFound(message) => (StatusCode::NOT_FOUND, message).into_response(),
            ApiErrors::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
        }
    }
}

/// Serialize an HTTP status code as its numeric value.
fn serialize_status_code<S>(x: &StatusCode, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u16(x.as_u16())
}

/// Handle internal server errors by logging and returning a generic message to clients.
///
/// Generates a unique error ID for tracking in logs.
fn handle_internal_server_error(err: Report) -> (StatusCode, String) {
    let error_id = Uuid::new_v4();
    tracing::error!("{error_id} - {err:?}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An internal server error has occurred. Error ID={error_id}"),
    )
}
