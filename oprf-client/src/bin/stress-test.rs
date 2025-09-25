use std::{path::PathBuf, time::Duration};

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use base64ct::{Base64, Encoding};
use clap::Parser;
use eyre::Context;
use oprf_client::{EdDSAPrivateKey, NullifierArgs};
use oprf_types::{
    RpId, ShareEpoch,
    crypto::RpNullifierKey,
    sc_mock::{RpKeys, UserPublicKey},
};

#[derive(Parser, Debug)]
struct StressTestConfig {
    /// Smart Contract mock
    #[clap(
        long,
        env = "OPRF_STRESS_CHAIN_URL",
        default_value = "http://127.0.0.1:6789"
    )]
    pub chain_url: String,

    /// Path to urls for the nodes
    #[clap(long, env = "OPRF_STRESS_SERVICES")]
    pub services: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("stress_test=trace,warn");
    let config = StressTestConfig::parse();

    tracing::info!(
        "loading urls from services from file: {}",
        config.services.display()
    );

    let urls = std::fs::read_to_string(config.chain_url)
        .context("while loading urls from file")?
        .lines()
        .collect::<Vec<_>>();
    tracing::info!("loaded {} urls", urls.len());

    tracing::info!("waiting for mock to be ready at: {}", config.chain_url);

    let client = reqwest::Client::new();

    loop {
        match client
            .get(format!("{}/health", config.chain_url))
            .send()
            .await
        {
            Ok(res) => {
                if res.status().is_success() {
                    break;
                }
                tracing::info!("another ping..");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {
                tracing::info!("another ping..");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    let rp_id = client
        .post(format!("{}/api/admin/register-new-rp", config.chain_url))
        .send()
        .await
        .context("while creating new rp")?
        .json::<RpId>()
        .await
        .context("while parsing RP id")?;
    tracing::info!("waiting for RP id: {rp_id}...");

    let key = loop {
        match client
            .get(format!(
                "{}/api/rp/{}",
                config.chain_url,
                rp_id.into_inner()
            ))
            .send()
            .await
            .context("not healthy anymore")?
            .json::<RpKeys>()
            .await
        {
            Ok(nullifier_key) => break nullifier_key,
            Err(_) => {
                tracing::info!("another ping..");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };
    let RpKeys { nullifier, sk } = key;
    let sk = k256::SecretKey::from_slice(&Base64::decode_vec(&sk).context("not valid base64")?);

    let my_sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let my_pk = my_sk.public();

    let mut merkle_pubkey = UserPublicKey::with_eddsa_pk(my_pk, &mut rand::thread_rng());

    let nullifier_args = NullifierArgs {
        rp_nullifier_key: nullifier.inner(),
        key_epoch: ShareEpoch::default(),
        sk: my_sk,
        pks: merkle_pubkey.0,
        pk_index: 0,
        merkle_root: todo!(),
        mt_index: todo!(),
        siblings: todo!(),
        rp_id,
        action: todo!(),
        signal_hash: todo!(),
        merkle_epoch: todo!(),
        nonce: todo!(),
        signature: todo!(),
        id_commitment_r: todo!(),
        degree: todo!(),
        query_pk: todo!(),
        query_matrices: todo!(),
        nullifier_pk: todo!(),
        nullifier_matrices: todo!(),
        cred_type_id: todo!(),
        cred_pk: todo!(),
        cred_sk: todo!(),
        cred_hashes: todo!(),
        genesis_issued_at: todo!(),
        expired_at: todo!(),
        current_time_stamp: todo!(),
    };

    Ok(())
}
