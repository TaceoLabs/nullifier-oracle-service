use axum::{
    Router,
    extract::{
        WebSocketUpgrade,
        ws::{self, CloseFrame, WebSocket, close_code},
    },
    routing::any,
};
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

use crate::{
    OprfReqAuthService, OprfReqError,
    services::oprf::{OprfService, OprfServiceError},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HumanReadable {
    Yes,
    No,
}

#[derive(Debug, thiserror::Error)]
enum WsErrors {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error(transparent)]
    AxumError(#[from] axum::Error),
    #[error("unexpected message")]
    UnexpectedMessage,
    #[error("Cannot authenticate: {0}")]
    AuthError(String),
    #[error(transparent)]
    OprfServiceError(#[from] OprfServiceError),
}
async fn ws<
    ReqAuth: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    ReqAuthError: OprfReqError,
>(
    ws: WebSocketUpgrade,
    oprf_service: OprfService,
    req_auth_service: OprfReqAuthService<ReqAuth, ReqAuthError>,
    max_message_size: usize,
    max_connection_lifetime: Duration,
) -> axum::response::Response {
    ws.max_message_size(max_message_size)
        .on_failed_upgrade(|err| {
            tracing::warn!("could not establish websocket connection: {err:?}");
        })
        .on_upgrade(move |mut ws| async move {
            let close_frame = match tokio::time::timeout(
                max_connection_lifetime,
                oprf::<ReqAuth, ReqAuthError>(&mut ws, oprf_service, req_auth_service),
            )
            .await
            {
                Ok(Ok(_)) => CloseFrame {
                    code: close_code::NORMAL,
                    reason: "success".into(),
                },
                Ok(Err(err)) => {
                    tracing::debug!("{err:?}");
                    match err {
                        WsErrors::ConnectionClosed => {
                            // nothing to do here
                            return;
                        }
                        WsErrors::AxumError(_) => CloseFrame {
                            code: close_code::ERROR,
                            reason: "unexpected error".into(),
                        },
                        WsErrors::UnexpectedMessage => CloseFrame {
                            code: close_code::UNSUPPORTED,
                            reason: "only text or binary".into(),
                        },
                        WsErrors::AuthError(reason) => CloseFrame {
                            code: close_code::POLICY,
                            reason: reason.into(),
                        },
                        WsErrors::OprfServiceError(_oprf_service_error) => todo!(),
                    }
                }
                Err(_) => CloseFrame {
                    code: close_code::AWAY,
                    reason: "timeout".into(),
                },
            };
            tracing::trace!("sending close frame");
            if ws.send(ws::Message::Close(Some(close_frame))).await.is_ok() {
                wait_for_close_frame(ws).await;
            }
        })
}

async fn wait_for_close_frame(mut socket: WebSocket) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async move {
        while let Some(Ok(msg)) = socket.recv().await {
            if let ws::Message::Close(_) = msg {
                tracing::trace!("received close frame!");
                break;
            }
        }
        // encountered an error or closed stream - this is also ok
        tracing::trace!("dirty close from peer but also ok");
    })
    .await;
}

async fn read_request<Msg: DeserializeOwned>(
    socket: &mut WebSocket,
) -> Result<(Msg, HumanReadable), WsErrors> {
    let res = match socket.recv().await.ok_or(WsErrors::ConnectionClosed)?? {
        ws::Message::Text(json) => (
            serde_json::from_slice::<Msg>(json.as_bytes())
                .map_err(|_| WsErrors::UnexpectedMessage)?,
            HumanReadable::Yes,
        ),
        ws::Message::Binary(cbor) => (
            ciborium::from_reader(cbor.as_ref()).map_err(|_| WsErrors::UnexpectedMessage)?,
            HumanReadable::No,
        ),
        ws::Message::Close(_) => return Err(WsErrors::ConnectionClosed),
        _ => return Err(WsErrors::UnexpectedMessage),
    };
    Ok(res)
}

async fn write_response<Msg: Serialize>(
    response: Msg,
    human_readable: HumanReadable,
    socket: &mut WebSocket,
) -> Result<(), WsErrors> {
    let msg = match human_readable {
        HumanReadable::Yes => {
            let msg = serde_json::to_string(&response).expect("Can serialize response");
            ws::Message::text(msg)
        }
        HumanReadable::No => {
            let mut buf = Vec::new();
            ciborium::into_writer(&response, &mut buf).expect("Can serialize response");
            ws::Message::binary(buf)
        }
    };
    socket.send(msg).await?;
    Ok(())
}

async fn oprf<
    ReqAuth: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    ReqAuthError: OprfReqError,
>(
    socket: &mut WebSocket,
    oprf_service: OprfService,
    req_auth_service: OprfReqAuthService<ReqAuth, ReqAuthError>,
) -> Result<(), WsErrors> {
    let (init_request, human_readable) = read_request::<OprfRequest<ReqAuth>>(socket).await?;
    let request_id = init_request.request_id;
    let party_id = oprf_service.party_id;

    req_auth_service
        .verify(&init_request)
        .await
        .map_err(|err| {
            tracing::debug!("Could not auth request: {err:?}");
            WsErrors::AuthError(err.to_string())
        })?;

    let (session, commitments) = oprf_service
        .init_oprf_session(
            request_id,
            init_request.share_identifier,
            init_request.blinded_query,
        )
        .await?;

    let response = OprfResponse {
        commitments,
        party_id,
    };

    write_response(response, human_readable, socket).await?;
    let (challenge, _) = read_request::<ChallengeRequest>(socket).await?;

    let proof_share = oprf_service.finalize_oprf_session(challenge, session)?;
    let challenge_response = ChallengeResponse { proof_share };
    write_response(challenge_response, human_readable, socket).await?;
    Ok(())
}

pub fn routes<
    ReqAuth: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    ReqAuthError: OprfReqError,
>(
    oprf_service: OprfService,
    req_auth_service: OprfReqAuthService<ReqAuth, ReqAuthError>,
    max_message_size: usize,
    max_connection_lifetime: Duration,
) -> Router {
    Router::new().route(
        "/oprf",
        any(move |websocket_upgrade| {
            ws::<ReqAuth, ReqAuthError>(
                websocket_upgrade,
                oprf_service,
                req_auth_service,
                max_message_size,
                max_connection_lifetime,
            )
        }),
    )
}
