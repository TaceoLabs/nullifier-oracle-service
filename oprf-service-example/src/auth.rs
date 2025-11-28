use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use oprf_service::OprfReqAuthenticator;
use oprf_types::api::v1::OprfRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ExampleOprfReqAuth;

/// Errors returned by the [`ExampleOprfReqAuthError`].
#[derive(Debug, thiserror::Error)]
#[allow(unused)]
pub(crate) enum ExampleOprfReqAuthError {
    #[error("invalid")]
    Invalid,
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for ExampleOprfReqAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ExampleOprfReqAuthError::Invalid => {
                (StatusCode::BAD_REQUEST, "invalid").into_response()
            }
            ExampleOprfReqAuthError::InternalServerError(err) => {
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

pub(crate) struct ExampleOprfReqAuthenticator;

#[async_trait]
impl OprfReqAuthenticator for ExampleOprfReqAuthenticator {
    type ReqAuth = ExampleOprfReqAuth;
    type ReqAuthError = ExampleOprfReqAuthError;

    async fn verify(
        &self,
        _request: &OprfRequest<Self::ReqAuth>,
    ) -> Result<(), Self::ReqAuthError> {
        Ok(())
    }
}
