use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct KeyGenConfig {
    /// The dir to write the private keys to
    #[clap(long, env = "PRIVATE_KEY_SECRET_ID")]
    pub private_key_secret_id: String,

    /// Overwrite secrets if they exist
    #[clap(long, env = "OVERWRITE")]
    pub overwrite: bool,
}

async fn upload_to_aws(
    client: &aws_sdk_secretsmanager::Client,
    secret_id: String,
    message: String,
    overwrite_old_keys: bool,
) -> eyre::Result<()> {
    // If we don't allow overwrite we simply create the secret and propagate any errors
    if !overwrite_old_keys {
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    nodes_telemetry::install_tracing("key_gen=info");
    let config = KeyGenConfig::parse();
    let KeyGenConfig {
        private_key_secret_id,
        overwrite,
    } = config;

    let client = aws_sdk_secretsmanager::Client::new(&aws_config::load_from_env().await);

    let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());
    let public_key = (ark_babyjubjub::EdwardsAffine::generator() * private_key).into_affine();

    tracing::info!(
        "uploading private key to AWS Secrets Manager with secret id {private_key_secret_id}.."
    );

    upload_to_aws(
        &client,
        private_key_secret_id,
        private_key.to_string(),
        overwrite,
    )
    .await?;

    tracing::info!("your public key is {public_key}");

    Ok(())
}
