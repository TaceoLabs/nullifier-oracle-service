use axum::{Json, http::StatusCode, response::IntoResponse};
use eyre::Report;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::services::rp_key_gen::RpNullifierGenServiceError;

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

pub type ApiResult<T> = Result<T, ApiErrors>;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ApiErrors {
    #[error("an explicit error was returned: {0:?}")]
    ExplicitError(ApiError),
    #[error("bad request: {0}")]
    BadRequest(String),
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

impl From<RpNullifierGenServiceError> for ApiErrors {
    fn from(value: RpNullifierGenServiceError) -> Self {
        tracing::debug!("{value:?}");
        match value {
            RpNullifierGenServiceError::UnknownRp(rp_id) => {
                ApiErrors::NotFound(format!("cannot find {rp_id}"))
            }
            RpNullifierGenServiceError::InRound1 => {
                ApiErrors::BadRequest(String::from("already in round2"))
            }
            RpNullifierGenServiceError::InRound2 => {
                ApiErrors::BadRequest(String::from("still in round 1"))
            }
            RpNullifierGenServiceError::AlreadySubmitted => {
                ApiErrors::BadRequest(String::from("you already submitted for this round"))
            }
        }
    }
}

impl IntoResponse for ApiErrors {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiErrors::ExplicitError(ApiError { message, code }) => {
                (code, message.unwrap_or(String::from("unknown error"))).into_response()
            }
            ApiErrors::BadRequest(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
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
