//! Conversions are provided from service-level errors like [`OprfServiceError`] into
//! API errors, ensuring consistent HTTP responses.
//!
//! All errors implement [`IntoResponse`] so they can be directly returned from Axum
//! handlers.

use axum::{http::StatusCode, response::IntoResponse};
use uuid::Uuid;

use crate::services::{oprf::OprfServiceError, oprf_key_material_store::OprfKeyMaterialStoreError};

impl IntoResponse for OprfServiceError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OprfServiceError::BlindedQueryIsIdentity => (
                StatusCode::BAD_REQUEST,
                "blinded query not allowed to be identity",
            )
                .into_response(),
            OprfServiceError::UnknownRequestId(id) => {
                (StatusCode::NOT_FOUND, format!("unknown request id: {id}")).into_response()
            }
            OprfServiceError::OprfKeyMaterialStoreError(err) => err.into_response(),
            OprfServiceError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for OprfKeyMaterialStoreError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OprfKeyMaterialStoreError::UnknownRp(rp_id) => (
                StatusCode::NOT_FOUND,
                format!("cannot find RP with id: {rp_id}"),
            )
                .into_response(),
            OprfKeyMaterialStoreError::UnknownShareEpoch(share_epoch) => (
                StatusCode::NOT_FOUND,
                format!("cannot find share with epoch {share_epoch}"),
            )
                .into_response(),
        }
    }
}
