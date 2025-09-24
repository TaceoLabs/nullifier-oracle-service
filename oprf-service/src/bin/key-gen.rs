use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use clap::Parser;
use oprf_types::crypto::{PeerPublicKey, PeerPublicKeyList};

#[derive(Parser, Debug)]
pub struct KeyGenConfig {
    /// The secret ID prefix for SC to look for the public keys
    #[clap(long, env = "PUBLIC_SC_ID_PREFIX", default_value = "oprf/sc/pubs")]
    pub sc_mock_public_key_id: String,

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

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("warn,key_gen=debug"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing();
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
    let pubs_json =
        serde_json::to_string(&PeerPublicKeyList::from(public_keys)).expect("can serialize");
    upload_to_aws(
        &config,
        &client,
        config.sc_mock_public_key_id.clone(),
        pubs_json,
    )
    .await?;
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
