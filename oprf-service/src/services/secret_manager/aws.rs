use std::str::FromStr;

use async_trait::async_trait;
use eyre::Context;
use tracing::instrument;

use crate::services::secret_manager::{PeerPrivateKey, SecretManager};

/// AWS Secret Manager client wrapper.
#[derive(Debug, Clone)]
pub(crate) struct AwsSecretManager {
    client: aws_sdk_secretsmanager::Client,
    private_key_secret_id: String,
}

impl AwsSecretManager {
    /// Initializes an AWS secret manager client.
    ///
    /// Loads AWS configuration from the environment and wraps the client
    /// in a `SecretManagerService`.
    pub(crate) async fn init(private_key_secret_id: String) -> Self {
        // loads the latest defaults for aws
        tracing::info!("initializing AWS secret manager from env...");
        let aws_config = aws_config::load_from_env().await;
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        AwsSecretManager {
            client,
            private_key_secret_id,
        }
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<PeerPrivateKey> {
        tracing::info!(
            "loading secret key from AWS with name {}...",
            self.private_key_secret_id
        );
        let private_key = self
            .client
            .get_secret_value()
            .secret_id(&self.private_key_secret_id)
            .send()
            .await
            .context("while retrieving secret key")?
            .secret_string()
            .expect("is string and not binary")
            .to_owned();
        let private_key = ark_babyjubjub::Fr::from_str(&private_key)
            .map_err(|_| eyre::eyre!("Cannot parse private key from AWS"))?;
        let private_key = PeerPrivateKey::from(private_key);

        Ok(private_key)
    }
}
