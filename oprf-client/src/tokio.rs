use eyre::Context;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use tokio::task::JoinSet;

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
        .json::<ChallengeResponse>()
        .await?)
}

pub async fn finish_sessions(
    oprf_services: &[String],
    req: ChallengeRequest,
) -> super::Result<Vec<ChallengeResponse>> {
    let client = reqwest::Client::new();
    futures::future::try_join_all(
        oprf_services
            .iter()
            .map(|service| oprf_challenge(client.clone(), service.to_owned(), req.clone())),
    )
    .await
}

pub async fn init_sessions(
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest,
) -> super::Result<(Vec<String>, Vec<OprfResponse>)> {
    let client = reqwest::Client::new();

    let mut requests = oprf_services
        .iter()
        .map(|service| oprf_request(client.clone(), service.to_owned(), req.to_owned()))
        .collect::<JoinSet<_>>();

    let mut services = Vec::with_capacity(oprf_services.len());
    let mut responses = Vec::with_capacity(oprf_services.len());
    while let Some(response) = requests.join_next().await {
        match response.context("can't join responses")? {
            Ok((service, response)) => {
                responses.push(response);
                services.push(service);
                if responses.len() == threshold {
                    break;
                }
            }
            Err(err) => {
                tracing::info!("Got error response: {err:?}");
            }
        }
    }

    if responses.len() == threshold {
        tracing::debug!("got 3 responses!");
        Ok((services, responses))
    } else {
        Err(super::Error::NotEnoughOprfResponses {
            n: responses.len(),
            threshold,
        })
    }
}
