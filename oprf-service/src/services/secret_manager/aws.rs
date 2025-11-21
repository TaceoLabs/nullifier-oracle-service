//! AWS Secret Manager Implementation
//!
//! This module provides an implementation of [`SecretManager`] using AWS Secrets Manager
//! to store and retrieve RP (Relying Party) secrets.
//!
//! The module supports both production and development environments:
//! - Production: Uses standard AWS credentials and configuration
//! - Development: Uses LocalStack with hardcoded test credentials
//!
//! Secrets are stored as JSON objects containing the RP's public key, nullifier key,
//! and current/previous epoch secrets.

use alloy::hex;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use k256::ecdsa::SigningKey;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use eyre::{Context, ContextCompat};
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::services::oprf_key_material_store::{OprfKeyMaterial, OprfKeyMaterialStore};
use crate::services::secret_manager::{SecretManager, StoreDLogShare};

/// AWS Secret Manager client wrapper.
#[derive(Debug, Clone)]
pub struct AwsSecretManager {
    client: aws_sdk_secretsmanager::Client,
    rp_secret_id_prefix: String,
    wallet_private_key_secret_id: String,
}

impl AwsSecretManager {
    /// Initializes an AWS secret manager client.
    ///
    /// Loads AWS configuration from the environment and wraps the client
    /// in a `SecretManagerService`.
    pub async fn init(
        aws_config: aws_config::SdkConfig,
        rp_secret_id_prefix: &str,
        wallet_private_key_secret_id: &str,
    ) -> Self {
        // loads the latest defaults for aws
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        AwsSecretManager {
            client,
            rp_secret_id_prefix: rp_secret_id_prefix.to_string(),
            wallet_private_key_secret_id: wallet_private_key_secret_id.to_string(),
        }
    }
}

/// JSON structure used to serialize secrets in AWS.
///
/// Stores the current and optionally previous epoch.
#[derive(Serialize, Deserialize)]
struct AwsRpSecret {
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    current: EpochSecret,
    // Is none for first secret
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: Option<EpochSecret>,
}

/// Secret associated with a single epoch.
#[derive(Clone, Serialize, Deserialize)]
struct EpochSecret {
    epoch: ShareEpoch,
    secret: DLogShareShamir,
}

impl AwsRpSecret {
    /// Creates a new secret for a given `OprfKeyId`.
    ///
    /// Current epoch is set to 0, previous is `None`.
    pub fn new(
        oprf_key_id: OprfKeyId,
        oprf_public_key: OprfPublicKey,
        secret: DLogShareShamir,
    ) -> Self {
        Self {
            oprf_key_id,
            oprf_public_key,
            current: EpochSecret {
                epoch: ShareEpoch::default(),
                secret,
            },
            previous: None,
        }
    }
}

impl From<AwsRpSecret> for OprfKeyMaterial {
    /// Converts an [`AwsRpSecret`] into [`OprfKeyMaterial`].
    ///
    /// Includes both current and previous epoch secrets if available.
    fn from(value: AwsRpSecret) -> Self {
        let mut shares = HashMap::new();
        shares.insert(value.current.epoch, value.current.secret);
        if let Some(previous) = value.previous {
            shares.insert(previous.epoch, previous.secret);
        }
        Self::new(shares, value.oprf_public_key)
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<SecretString> {
        tracing::debug!(
            "checking if there exists a private key at: {}",
            self.wallet_private_key_secret_id
        );
        let hex_private_key = match self
            .client
            .get_secret_value()
            .secret_id(&self.wallet_private_key_secret_id)
            .send()
            .await
        {
            Ok(secret_string) => {
                tracing::info!("loaded wallet private key from secret-manager");
                SecretString::from(
                    secret_string
                        .secret_string()
                        .context("expected string private-key, but is byte")?
                        .to_owned(),
                )
            }
            Err(x) => {
                match x.into_service_error() {
                    GetSecretValueError::ResourceNotFoundException(_) => {
                        tracing::info!("secret not found - will create wallet");
                        // Create a new wallet
                        let private_key = SigningKey::random(&mut rand::thread_rng());
                        let hex_string = hex::encode_prefixed(private_key.to_bytes());
                        tracing::debug!("uploading secret to AWS..");
                        self.client
                            .create_secret()
                            .name(&self.wallet_private_key_secret_id)
                            .secret_string(&hex_string)
                            .send()
                            .await
                            .context("while creating wallet secret")?;
                        SecretString::from(hex_string)
                    }
                    x => Err(x)?,
                }
            }
        };
        Ok(hex_private_key)
    }

    /// Loads all secrets from AWS Secrets Manager.
    ///
    /// Iterates through all secrets with the configured prefix and deserializes them into an [`OprfKeyMaterialStore`].
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore> {
        tracing::debug!(
            "loading rp secrets with prefix: {}",
            self.rp_secret_id_prefix
        );
        let mut oprf_key_materials = HashMap::new();
        let mut next_token = None;
        loop {
            let secrets = self
                .client
                .list_secrets()
                .set_next_token(next_token)
                .filters(
                    Filter::builder()
                        .key(FilterNameStringType::Name)
                        .values(&self.rp_secret_id_prefix)
                        .build(),
                )
                .send()
                .await?;
            tracing::debug!("got {} secrets", secrets.secret_list().len());
            for secret in secrets.secret_list() {
                if let Some(name) = secret.name() {
                    // The filter is a substring match, so double-check the prefix
                    if name.starts_with(&self.rp_secret_id_prefix) {
                        let secret_value = self
                            .client
                            .get_secret_value()
                            .secret_id(name)
                            .send()
                            .await
                            .context("while retrieving secret key")?
                            .secret_string()
                            .expect("is string and not binary")
                            .to_owned();
                        let rp_secret: AwsRpSecret = serde_json::from_str(&secret_value)
                            .context("Cannot deserialize AWS Secret")?;
                        tracing::debug!("loaded secret for oprf_key_id: {}", rp_secret.oprf_key_id);
                        oprf_key_materials.insert(rp_secret.oprf_key_id, rp_secret.into());
                    }
                }
            }

            // if a next_token was returned, there are more secrets to load
            // in that case we include it in the next request and continue
            next_token = secrets.next_token;
            if next_token.is_none() {
                break;
            }
        }
        Ok(OprfKeyMaterialStore::new(oprf_key_materials))
    }

    /// Stores a new DLog share for an RP in AWS Secrets Manager.
    ///
    /// Creates a new secret with the configured prefix and RP ID.
    #[instrument(level = "info", skip_all)]
    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()> {
        let StoreDLogShare {
            oprf_key_id,
            oprf_public_key,
            share,
        } = store;
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, oprf_key_id);
        let secret = AwsRpSecret::new(oprf_key_id, oprf_public_key, share);
        self.client
            .create_secret()
            .name(secret_id)
            .secret_string(serde_json::to_string(&secret).expect("can serialize"))
            .send()
            .await
            .context("while creating secret")?;
        tracing::info!("created new rp secret for {oprf_key_id}");
        Ok(())
    }

    /// Removes an RP's secret from AWS Secrets Manager.
    ///
    /// Permanently deletes the secret without recovery period.
    #[instrument(level = "info", skip(self))]
    async fn remove_dlog_share(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, oprf_key_id);
        self.client
            .delete_secret()
            .secret_id(secret_id)
            .force_delete_without_recovery(true)
            .send()
            .await
            .context("while deleting DLog Share")?;
        tracing::info!("deleted secret from AWS {oprf_key_id}");
        Ok(())
    }

    /// Updates an RP's secret with a new epoch.
    ///
    /// Loads the existing secret, moves the current epoch to previous,
    /// and stores the new share as the current epoch.
    #[instrument(level = "info", skip(self, share))]
    async fn update_dlog_share(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        share: DLogShareShamir,
    ) -> eyre::Result<()> {
        // Load old secret to preserve previous epoch
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, oprf_key_id);
        tracing::info!("loading old secret first at {secret_id}");
        let secret_value = self
            .client
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send()
            .await
            .context("while loading old secret")?
            .secret_string()
            .expect("is string and not binary")
            .to_owned();

        let mut rp_secret: AwsRpSecret =
            serde_json::from_str(&secret_value).context("Cannot deserialize AWS Secret")?;

        let prev_epoch = rp_secret.current.epoch;

        rp_secret.previous = Some(rp_secret.current.clone());
        rp_secret.current = EpochSecret {
            epoch,
            secret: share,
        };

        self.client
            .put_secret_value()
            .secret_id(secret_id)
            .secret_string(serde_json::to_string(&rp_secret).expect("can serialize"))
            .send()
            .await
            .context("while storing new secret")?;
        tracing::debug!(
            "updated rp secret for {oprf_key_id} with current: {epoch}, previous: {prev_epoch}"
        );
        Ok(())
    }
}

/// Constructs the full secret ID for an RP in AWS Secrets Manager.
///
/// Combines the prefix with the RP ID.
#[inline(always)]
fn to_rp_secret_id(rp_secret_id_prefix: &str, rp: OprfKeyId) -> String {
    format!("{}/{}", rp_secret_id_prefix, rp.into_inner())
}

#[cfg(test)]
pub mod tests {
    use crate::{AwsSecretManager, SecretManager as _};
    use aws_config::Region;
    use aws_sdk_secretsmanager::config::Credentials;
    use secrecy::ExposeSecret;
    use testcontainers_modules::{
        localstack::LocalStack,
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };

    const WALLET_SECRET_ID: &str = "wallet_secret_id";
    const RP_SECRET_ID_PREFIX: &str = "rp_suffix";
    async fn localstack_testcontainer() -> eyre::Result<(ContainerAsync<LocalStack>, String)> {
        let container = LocalStack::default()
            .with_env_var("SERVICES", "secretsmanager")
            .start()
            .await?;
        let host_ip = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(4566).await?;
        let endpoint_url = format!("http://{host_ip}:{host_port}");
        Ok((container, endpoint_url))
    }

    pub async fn localstack_client(
        url: &str,
    ) -> (aws_sdk_secretsmanager::Client, aws_config::SdkConfig) {
        let region_provider = Region::new("us-east-1");
        let credentials = Credentials::new("test", "test", None, None, "Static");
        // use TEST_AWS_ENDPOINT_URL if set in testcontainer
        let aws_config = aws_config::from_env()
            .region(region_provider)
            .endpoint_url(url)
            .credentials_provider(credentials)
            .load()
            .await;
        (aws_sdk_secretsmanager::Client::new(&aws_config), aws_config)
    }

    pub async fn load_secret(
        client: aws_sdk_secretsmanager::Client,
        secret_id: &str,
    ) -> eyre::Result<String> {
        let secret = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("is not a secret-string"))?
            .to_owned();
        Ok(secret)
    }

    #[tokio::test]
    async fn load_eth_wallet_empty() -> eyre::Result<()> {
        let (_localstack_container, localstack_url) = localstack_testcontainer().await?;
        let (client, config) = localstack_client(&localstack_url).await;
        let secret_manager =
            AwsSecretManager::init(config, RP_SECRET_ID_PREFIX, WALLET_SECRET_ID).await;
        let _ = load_secret(client.clone(), WALLET_SECRET_ID)
            .await
            .expect_err("should not be there");

        let secret_string_new_created = secret_manager.load_or_insert_wallet_private_key().await?;
        let secret_string_loading = secret_manager.load_or_insert_wallet_private_key().await?;
        assert_eq!(
            secret_string_new_created.expose_secret(),
            secret_string_loading.expose_secret()
        );
        let is_secret = load_secret(client, WALLET_SECRET_ID).await?;
        assert_eq!(is_secret, secret_string_new_created.expose_secret());

        Ok(())
    }
}
