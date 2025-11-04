use std::time::Duration;

use oprf_types::{RpId, api::v1::PublicRpMaterial};
use reqwest::StatusCode;
use tokio::task::JoinSet;

async fn health_check(health_url: String) {
    loop {
        if reqwest::get(&health_url).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tracing::info!("healthy: {health_url}");
}

pub async fn services_health_check(
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let health_checks = services
        .iter()
        .map(|service| health_check(format!("{service}/health")))
        .collect::<JoinSet<_>>();

    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| eyre::eyre!("services not healthy in provided time: {max_wait_time:?}"))?;
    Ok(())
}

async fn load_public_rp_material(rp_material_url: String) -> PublicRpMaterial {
    loop {
        if let Ok(response) = reqwest::get(&rp_material_url).await {
            if let Ok(response) = response.error_for_status() {
                if let Ok(material) = response.json::<PublicRpMaterial>().await {
                    return material;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn rp_material_from_services(
    rp_id: RpId,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<PublicRpMaterial> {
    let rp_material_checks = services
        .iter()
        .map(|service| load_public_rp_material(format!("{service}/rp/{rp_id}")))
        .collect::<JoinSet<_>>();
    match tokio::time::timeout(max_wait_time, rp_material_checks.join_all())
        .await
        .map_err(|_| eyre::eyre!("could not load rp material in provided time: {max_wait_time:?}"))
    {
        Ok(mut keys) => {
            let key = keys.pop().expect("at least one here");
            if keys.into_iter().all(|other| key == other) {
                Ok(key)
            } else {
                eyre::bail!("keys did not match for all services");
            }
        }
        Err(_) => eyre::bail!("couldn't load rp material within time"),
    }
}
async fn rp_material_not_known_check(health_url: String) {
    loop {
        if let Ok(response) = reqwest::get(&health_url).await {
            if let Err(err) = response.error_for_status() {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn assert_rp_unknown(
    rp_id: RpId,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let health_checks = services
        .iter()
        .map(|service| rp_material_not_known_check(format!("{service}/rp/{rp_id}")))
        .collect::<JoinSet<_>>();
    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!("services still have RpMaterial {rp_id} after: {max_wait_time:?}")
        })?;
    Ok(())
}
