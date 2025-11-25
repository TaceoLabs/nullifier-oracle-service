use super::Error;
use oprf_types::api::v1::OprfResponse;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest};
use serde::{Serialize, de::DeserializeOwned};
use tokio::task::JoinSet;
use tracing::instrument;

use crate::OprfSessions;

/// Sends an `init` request to one OPRF peer.
///
/// Returns the peer's URL alongside the parsed [`OprfResponse`].
#[instrument(level = "trace", skip(client, req))]
async fn oprf_request<T: Clone + Serialize + DeserializeOwned>(
    client: reqwest::Client,
    service: String,
    req: OprfRequest<T>,
) -> Result<(String, OprfResponse), super::Error> {
    let url = format!("{service}/api/v1/init");
    tracing::trace!("> sending request to {url}..");
    let response = client.post(url).json(&req).send().await?;
    if response.status().is_success() {
        let response = response.json::<OprfResponse>().await?;
        Ok((service, response))
    } else {
        let status = response.status();
        let message = response.text().await?;
        Err(Error::ApiError { status, message })
    }
}

/// Sends a `challenge` request to one OPRF service.
///
/// Returns the parsed [`ChallengeResponse`].
#[instrument(level = "trace", skip(client, req))]
async fn oprf_challenge(
    client: reqwest::Client,
    service: String,
    req: ChallengeRequest,
) -> Result<ChallengeResponse, super::Error> {
    let url = format!("{service}/api/v1/finish");
    tracing::trace!("> sending request to {url}..");
    let response = client.post(url).json(&req).send().await?;
    if response.status().is_success() {
        let response = response.json::<ChallengeResponse>().await?;
        Ok(response)
    } else {
        let status = response.status();
        let message = response.text().await?;
        Err(Error::ApiError { status, message })
    }
}

/// Completes all OPRF sessions in parallel by calling `/api/v1/finish`
/// on every peer in the [`OprfSessions`].
///
/// **Important:**  
/// - These must be the *same parties* that were used during the initial
///   `init_sessions` call.
/// - The order of the peers matters: we return responses in the order provided and they need
///   to match the original session list. This is crucial because Lagrange coefficients are
///   computed in the meantime, and they need to match the shares obtained earlier.
///
/// Fails fast if any single request errors out.
#[instrument(level = "debug", skip_all)]
pub async fn finish_sessions(
    client: &reqwest::Client,
    sessions: OprfSessions,
    req: ChallengeRequest,
) -> Result<Vec<ChallengeResponse>, super::Error> {
    futures::future::try_join_all(
        sessions
            .services
            .iter()
            .map(|service| oprf_challenge(client.clone(), service.to_owned(), req.clone())),
    )
    .await
}

/// Initializes new OPRF sessions by calling `/api/v1/init`
/// on a list of peers, collecting responses until the
/// given `threshold` is met.
///
/// Peers are queried concurrently. Errors from some services
/// are logged and ignored, unless they prevent reaching the threshold.
///
/// Returns an [`OprfSessions`] ready to be finalized with [`finish_sessions`].
#[instrument(level = "debug", skip_all)]
pub async fn init_sessions<Auth: Clone + Serialize + DeserializeOwned + Send + Sync + 'static>(
    client: &reqwest::Client,
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest<Auth>,
) -> Result<OprfSessions, super::Error> {
    let mut requests = oprf_services
        .iter()
        .map(|service| oprf_request(client.clone(), service.to_owned(), req.to_owned()))
        .collect::<JoinSet<_>>();

    let mut sessions = OprfSessions::with_capacity(threshold);
    while let Some(response) = requests.join_next().await {
        match response.expect("Task did not panic") {
            Ok((service, response)) => {
                tracing::trace!("Got response from {service}");
                sessions.push(service, response);
                if sessions.len() == threshold {
                    break;
                }
            }
            Err(err) => {
                // we very much expect certain services to return an error therefore we do not log at warn/error level.
                tracing::debug!("Got error response: {err:?}");
            }
        }
    }

    if sessions.len() == threshold {
        Ok(sessions)
    } else {
        Err(super::Error::NotEnoughOprfResponses {
            n: sessions.len(),
            threshold,
        })
    }
}
