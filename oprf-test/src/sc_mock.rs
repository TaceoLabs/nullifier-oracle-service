use std::time::Duration;

use oprf_client::{MAX_DEPTH, MerkleMembership};
use oprf_types::{
    RpId,
    crypto::{RpNullifierKey, UserPublicKeyBatch},
    sc_mock::{AddPublicKeyRequest, AddPublicKeyResponse, SignNonceRequest, SignNonceResponse},
};
use smart_contract_mock::config::SmartContractMockConfig;

type BaseField = ark_babyjubjub::Fq;

pub async fn start_smart_contract_mock() -> String {
    let url = "http://localhost:6789".to_string();
    let config = SmartContractMockConfig {
        bind_addr: "0.0.0.0:6789".parse().expect("can parse"),
        max_root_cache_size: 10,
        add_pk_interval: Duration::from_secs(30),
        init_rp_registry: 1,
        add_rp_interval: Duration::from_secs(30),
        seed: 42,
        oprf_services: 3,
        oprf_degree: 1,
        oprf_public_keys_secret_id: "oprf/sc/pubs".to_string(),
        merkle_depth: MAX_DEPTH,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = smart_contract_mock::start(config, never).await;
        eprintln!("smart contract mock failed to start: {res:?}");
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("cannot start smart contract mock");
    url
}

pub async fn register_rp(chain_url: &str) -> eyre::Result<(RpId, RpNullifierKey)> {
    let client = reqwest::Client::new();
    let rp_id = client
        .post(format!("{chain_url}/api/admin/register-new-rp"))
        .send()
        .await?
        .json::<RpId>()
        .await?;
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let res = client
                .get(format!("{chain_url}/api/rp/{}", rp_id.into_inner()))
                .send()
                .await
                .expect("smart contract is online");
            if res.status().is_success() {
                break res.json::<RpNullifierKey>().await.expect("can deserialize");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("can fetch");
    Ok((rp_id, rp_nullifier_key))
}

pub async fn register_public_key(
    chain_url: &str,
    public_key: &UserPublicKeyBatch,
) -> eyre::Result<MerkleMembership> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{chain_url}/api/admin/register-new-public-key"))
        .json(&AddPublicKeyRequest {
            public_key: public_key.to_owned(),
        })
        .send()
        .await
        .expect("smart contract is online");
    if res.status().is_success() {
        let res = res
            .json::<AddPublicKeyResponse>()
            .await
            .expect("can get merkle path");
        Ok(MerkleMembership {
            epoch: res.epoch,
            root: res.path.root,
            depth: MAX_DEPTH as u64,
            mt_index: res.path.index,
            siblings: res
                .path
                .siblings
                .try_into()
                .expect("siblings has correct length"),
        })
    } else {
        eyre::bail!("returned error: {:?}", res.text().await?);
    }
}

pub async fn sign_nonce(
    chain_url: &str,
    rp_id: RpId,
    nonce: BaseField,
) -> eyre::Result<SignNonceResponse> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{chain_url}/api/rp/sign"))
        .json(&SignNonceRequest { rp_id, nonce })
        .send()
        .await
        .expect("smart contract is online");
    if res.status().is_success() {
        let res = res
            .json::<SignNonceResponse>()
            .await
            .expect("can get merkle path");
        Ok(res)
    } else {
        eyre::bail!("returned error: {:?}", res.text().await?);
    }
}
