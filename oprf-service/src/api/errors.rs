use axum::{Json, http::StatusCode, response::IntoResponse};
use eyre::Report;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::services::oprf::OprfServiceError;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub message: Option<String>,
    #[serde(serialize_with = "serialize_status_code")]
    pub code: StatusCode,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.code, Json(self)).into_response()
    }
}

#[expect(dead_code)]
pub type ApiResult<T> = Result<T, ApiErrors>;

#[derive(Debug, thiserror::Error)]
pub enum ApiErrors {
    #[error("an explicit error was returned: {0:?}")]
    ExplicitError(ApiError),
    #[error("user is not authorized to perform this action")]
    Unauthorized,
    #[error("Cannot find resource: \"{0}\"")]
    NotFound(String),
    #[error(transparent)]
    InternalSeverError(#[from] eyre::Report),
}

impl From<ApiError> for ApiErrors {
    fn from(inner: ApiError) -> Self {
        ApiErrors::ExplicitError(inner)
    }
}

impl From<OprfServiceError> for ApiErrors {
    fn from(value: OprfServiceError) -> Self {
        tracing::debug!("{value:?}");
        match value {
            OprfServiceError::InvalidProof => ApiErrors::Unauthorized,
            OprfServiceError::UnknownRequestId(request) => ApiErrors::NotFound(request.to_string()),
            OprfServiceError::InternalServerErrpr(report) => ApiErrors::InternalSeverError(report),
            OprfServiceError::UnknownRpKeyEpoch(key_identifier) => ApiErrors::NotFound(format!(
                "Cannot find share for rp_id: {} , epoch: {}",
                key_identifier.rp_id, key_identifier.key_epoch
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
            ApiErrors::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "User is not authorized to perform this action",
            )
                .into_response(),
            ApiErrors::NotFound(message) => (StatusCode::NOT_FOUND, message).into_response(),
        }
    }
}

fn serialize_status_code<S>(x: &StatusCode, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u16(x.as_u16())
}

fn handle_internal_server_error(err: Report) -> (StatusCode, String) {
    let error_id = Uuid::new_v4();
    tracing::error!("{error_id} - {err:?}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An internal server error has occurred. Error ID={error_id}"),
    )
}
