use alloy::{hex, signers::local::PrivateKeySigner};
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use clap::Parser;
use k256::ecdsa::SigningKey;

#[derive(Parser, Debug)]
pub struct Config {
    /// The private key secret id
    #[clap(long, env = "PRIVATE_KEY_SECRET_ID", default_value = "private-key")]
    pub private_key_secret_id: String,

    /// Overwrite the private key
    #[clap(long, env = "OVERWRITE")]
    pub overwrite: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let tracing_config = nodes_telemetry::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_telemetry::initialize_tracing(&tracing_config)?;

    let mut rng = rand::thread_rng();
    let config = Config::parse();

    let aws_config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&aws_config);

    let private_key = SigningKey::random(&mut rng);
    let private_key_hex = hex::encode_prefixed(private_key.to_bytes());
    let signer = PrivateKeySigner::from_signing_key(private_key);
    let wallet_address = signer.address();

    tracing::info!(
        "creating private key secret with id \"{}\"",
        config.private_key_secret_id
    );
    if let Err(err) = client
        .create_secret()
        .name(&config.private_key_secret_id)
        .secret_string(&private_key_hex)
        .send()
        .await
    {
        match err.into_service_error() {
            CreateSecretError::ResourceExistsException(_) => {
                if config.overwrite {
                    client
                        .put_secret_value()
                        .secret_id(&config.private_key_secret_id)
                        .secret_string(&private_key_hex)
                        .send()
                        .await?;
                } else {
                    tracing::info!(
                        "secret already exists, use --overwrite if you want to overwrite it"
                    );
                    std::process::exit(0);
                }
            }
            x => Err(x)?,
        }
    }

    tracing::info!("wallet address: {wallet_address}");
    Ok(())
}
