use ark_ff::UniformRand;
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct KeyGenConfig {
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

    for i in 0..config.amount_parties {
        let secret_id = format!("{}/n{i}", config.secret_id_prefix);
        tracing::debug!("creating secret: {secret_id}");
        let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());

        // If we don't allow overwrite we simply create the secret and propagate any errors
        if !config.overwrite_old_keys {
            client
                .create_secret()
                .name(secret_id)
                .secret_string(private_key.to_string())
                .send()
                .await?;
        } else {
            // Try to create first, if it exists then add a new version
            match client
                .create_secret()
                .name(secret_id.clone())
                .secret_string(private_key.to_string())
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
                            .secret_string(private_key.to_string())
                            .send()
                            .await?;
                    }
                    x => Err(x)?,
                },
            }
        }
    }
    Ok(())
}
