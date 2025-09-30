use eyre::Context;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use tokio::task::JoinSet;

use crate::OprfSessions;

async fn oprf_request(
    client: reqwest::Client,
    service: String,
    req: OprfRequest,
) -> super::Result<(String, OprfResponse)> {
    let response = client
        .post(format!("{service}/api/v1/init"))
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .json::<OprfResponse>()
        .await?;
    Ok((service, response))
}

async fn oprf_challenge(
    client: reqwest::Client,
    service: String,
    req: ChallengeRequest,
) -> super::Result<ChallengeResponse> {
    Ok(client
        .post(format!("{service}/api/v1/finish"))
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .json::<ChallengeResponse>()
        .await?)
}

pub async fn finish_sessions(
    sessions: OprfSessions,
    req: ChallengeRequest,
) -> super::Result<Vec<ChallengeResponse>> {
    let client = reqwest::Client::new();
    futures::future::try_join_all(
        sessions
            .services
            .iter()
            .map(|service| oprf_challenge(client.clone(), service.to_owned(), req.clone())),
    )
    .await
}

pub async fn init_sessions(
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest,
) -> super::Result<OprfSessions> {
    let client = reqwest::Client::new();

    let mut requests = oprf_services
        .iter()
        .map(|service| oprf_request(client.clone(), service.to_owned(), req.to_owned()))
        .collect::<JoinSet<_>>();

    let mut sessions = OprfSessions::with_capacity(threshold);
    while let Some(response) = requests.join_next().await {
        match response.context("can't join responses")? {
            Ok((service, response)) => {
                sessions.push(service, response);
                if sessions.len() == threshold {
                    break;
                }
            }
            Err(err) => {
                eprintln!("Got error response: {err:?}");
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
