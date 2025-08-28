use axum::{Json, http::StatusCode, response::IntoResponse};
use eyre::Report;
use serde::{Serialize, Serializer};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub message: Option<String>,
    #[serde(serialize_with = "serialize_status_code")]
    #[schema(value_type=u16)]
    pub code: StatusCode,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.code, Json(self)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiErrors>;

#[derive(Debug, thiserror::Error)]
pub enum ApiErrors {
    #[error("an explict error was returned: {0:?}")]
    ExplicitError(ApiError),
    #[error("user is not authorized to perform this action")]
    Unauthorized,
    #[error("user sent a misformed request: \"{0}\"")]
    BadRequest(String),
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

impl IntoResponse for ApiErrors {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiErrors::ExplicitError(ApiError { message, code }) => {
                (code, message.unwrap_or(String::from("unknown error"))).into_response()
            }
            ApiErrors::InternalSeverError(inner) => {
                handle_internal_server_error(inner).into_response()
            }
            ApiErrors::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
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
