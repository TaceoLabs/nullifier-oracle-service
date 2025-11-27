//! This module defines the [`Error`] the websocket connection may encounter during a OPRF request. It further provides a method to transform the encountered errors into a close frame if necessary.

use crate::services::oprf_key_material_store::OprfKeyMaterialStoreError;
use axum::extract::ws::{CloseFrame, close_code};
use oprf_types::api::v1::oprf_error_codes;

/// All errors that may occur during an OPRF request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error("unexpected message")]
    UnexpectedMessage,
    #[error("cannot authenticate: {0}")]
    Auth(String),
    #[error("bad request: {0}")]
    BadRequest(String),
}

impl Error {
    /// Transforms the error into a [`CloseFrame`](https://docs.rs/axum/latest/axum/extract/ws/struct.CloseFrame.html) if necessary.
    pub(crate) fn into_close_frame(self) -> Option<CloseFrame> {
        tracing::debug!("{self:?}");
        match self {
            Error::ConnectionClosed => {
                // nothing to do here
                None
            }
            Error::Axum(_) => Some(CloseFrame {
                code: close_code::ERROR,
                reason: "unexpected error".into(),
            }),
            Error::UnexpectedMessage => Some(CloseFrame {
                code: close_code::UNSUPPORTED,
                reason: "only text or binary".into(),
            }),
            err @ Error::Auth(_) => Some(CloseFrame {
                code: close_code::POLICY,
                reason: err.to_string().into(),
            }),
            err @ Error::BadRequest(_) => Some(CloseFrame {
                code: oprf_error_codes::BAD_REQUEST,
                reason: err.to_string().into(),
            }),
        }
    }
}

impl From<OprfKeyMaterialStoreError> for Error {
    fn from(value: OprfKeyMaterialStoreError) -> Self {
        // we bind it like this in case we add an error later, the compiler will scream at us.
        match value {
            err @ OprfKeyMaterialStoreError::UnknownOprfKeyId(_)
            | err @ OprfKeyMaterialStoreError::UnknownShareEpoch(_) => {
                Self::BadRequest(err.to_string())
            }
        }
    }
}
