use std::path::PathBuf;

use alloy::hex;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use clap::Parser;
use eyre::Context;
use oprf_types::crypto::{PeerPublicKey, PeerPublicKeyList};

#[derive(Parser, Debug)]
pub struct KeyGenConfig {
    /// The path where to store the public keys to then be loaded from smart-contract.
    ///
    /// Will append this Path to `CARGO_MANIFEST_DIR`.
    #[clap(
        long,
        env = "PUBLIC_KEYS_FILE",
        default_value = "../contracts/script/script-data/pubkey-list.hex"
    )]
    pub path_to_pubkey_file: PathBuf,

    /// The secret ID prefix
    ///
    /// The final secret ID will then be `secret_id0`|`PartyID`
    #[clap(long, env = "SECRET_ID_PREFIX", default_value = "oprf/sk")]
    pub secret_id_prefix: String,

    /// The amount of keys that should be generated
    #[clap(long, env = "AMOUNT_PARTIES", default_value = "3")]
    pub amount_parties: usize,

    /// Whether old keys should be overwritten
    #[clap(long, env = "OVERWRITE", default_value = "false")]
    pub overwrite_old_keys: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("key_gen=debug");
    let config = KeyGenConfig::parse();
    tracing::info!(
        "generating private keys for {} services",
        config.amount_parties
    );
    tracing::debug!("prefix: {}", config.secret_id_prefix);
    tracing::debug!("overwrite: {}", config.overwrite_old_keys);
    let client = aws_sdk_secretsmanager::Client::new(&aws_config::load_from_env().await);

    let mut public_keys = Vec::with_capacity(config.amount_parties);
    for i in 0..config.amount_parties {
        let secret_id = format!("{}/n{i}", config.secret_id_prefix);
        let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());
        upload_to_aws(&config, &client, secret_id, private_key.to_string()).await?;
        public_keys.push(PeerPublicKey::from(
            (ark_babyjubjub::EdwardsAffine::generator() * private_key).into_affine(),
        ));
    }
    let key_list = PeerPublicKeyList::from(public_keys);
    let hex = hex::encode_prefixed(
        bincode::serde::encode_to_vec(&key_list, bincode::config::standard())
            .context("while serializing pub keys")?,
    );
    let manifest_dir = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
    let target_path = manifest_dir.join(config.path_to_pubkey_file);
    tracing::debug!("writing hex string to {}", target_path.display());
    std::fs::write(target_path, hex).context("while writing pubkey file")?;

    Ok(())
}

async fn upload_to_aws(
    config: &KeyGenConfig,
    client: &aws_sdk_secretsmanager::Client,
    secret_id: String,
    message: String,
) -> eyre::Result<()> {
    // If we don't allow overwrite we simply create the secret and propagate any errors
    if !config.overwrite_old_keys {
        tracing::debug!("creating secret: {secret_id}");
        client
            .create_secret()
            .name(secret_id)
            .secret_string(message)
            .send()
            .await?;
    } else {
        tracing::debug!("creating secret: {secret_id}");
        // Try to create first, if it exists then add a new version
        match client
            .create_secret()
            .name(secret_id.clone())
            .secret_string(message.clone())
            .send()
            .await
        {
            Ok(_) => (),
            Err(e) => match e.into_service_error() {
                CreateSecretError::ResourceExistsException(_) => {
                    // Resource exist so do put
                    tracing::debug!("already exists - overwrite");
                    client
                        .put_secret_value()
                        .secret_id(secret_id)
                        .secret_string(message)
                        .send()
                        .await?;
                }
                x => Err(x)?,
            },
        }
    }
    Ok(())
}
