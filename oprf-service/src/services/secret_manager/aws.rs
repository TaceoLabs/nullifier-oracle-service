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

use std::collections::HashMap;

use async_trait::async_trait;
use aws_config::Region;
use aws_sdk_secretsmanager::config::Credentials;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use eyre::Context;
use oprf_types::crypto::RpNullifierKey;
use oprf_types::{RpId, ShareEpoch};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::config::Environment;
use crate::services::rp_material_store::{RpMaterial, RpMaterialStore};
use crate::services::secret_manager::{DLogShare, SecretManager, StoreDLogShare};

/// AWS Secret Manager client wrapper.
#[derive(Debug, Clone)]
pub(crate) struct AwsSecretManager {
    client: aws_sdk_secretsmanager::Client,
    rp_secret_id_prefix: String,
}

impl AwsSecretManager {
    /// Initializes an AWS secret manager client.
    ///
    /// Loads AWS configuration from the environment and wraps the client
    /// in a `SecretManagerService`.
    pub(crate) async fn init(rp_secret_id_prefix: String, environment: Environment) -> Self {
        // loads the latest defaults for aws
        tracing::info!("initializing AWS secret manager from env...");
        let aws_config = match environment {
            Environment::Prod => aws_config::load_from_env().await,
            Environment::Dev => {
                tracing::info!("using localstack config");
                let region_provider = Region::new("us-east-1");
                let credentials = Credentials::new("test", "test", None, None, "Static");
                // use TEST_AWS_ENDPOINT_URL if set in testcontainer
                aws_config::from_env()
                    .region(region_provider)
                    .endpoint_url(
                        std::env::var("TEST_AWS_ENDPOINT_URL")
                            .unwrap_or("http://localhost:4566".to_string()),
                    )
                    .credentials_provider(credentials)
                    .load()
                    .await
            }
        };
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        AwsSecretManager {
            client,
            rp_secret_id_prefix,
        }
    }
}

/// JSON structure used to serialize secrets in AWS.
///
/// Stores the current and optionally previous epoch.
#[derive(Serialize, Deserialize)]
struct AwsRpSecret {
    rp_id: RpId,
    rp_public: k256::PublicKey,
    rp_nullifier_key: RpNullifierKey,
    current: EpochSecret,
    // Is none for first secret
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: Option<EpochSecret>,
}

/// Secret associated with a single epoch.
#[derive(Clone, Serialize, Deserialize)]
struct EpochSecret {
    epoch: ShareEpoch,
    secret: DLogShare,
}

impl AwsRpSecret {
    /// Creates a new secret for a given `RpId`.
    ///
    /// Current epoch is set to 0, previous is `None`.
    fn new(
        rp_id: RpId,
        rp_public: k256::PublicKey,
        rp_nullifier_key: RpNullifierKey,
        secret: DLogShare,
    ) -> Self {
        Self {
            rp_id,
            rp_public,
            rp_nullifier_key,
            current: EpochSecret {
                epoch: ShareEpoch::default(),
                secret,
            },
            previous: None,
        }
    }
}

impl From<AwsRpSecret> for RpMaterial {
    /// Converts an [`AwsRpSecret`] into [`RpMaterial`].
    ///
    /// Includes both current and previous epoch secrets if available.
    fn from(value: AwsRpSecret) -> Self {
        let mut shares = HashMap::new();
        shares.insert(value.current.epoch, value.current.secret);
        if let Some(previous) = value.previous {
            shares.insert(previous.epoch, previous.secret);
        }
        Self::new(shares, value.rp_public.into(), value.rp_nullifier_key)
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    /// Loads all RP secrets from AWS Secrets Manager.
    ///
    /// Iterates through all secrets with the configured prefix and deserializes
    /// them into an [`RpMaterialStore`].
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<RpMaterialStore> {
        tracing::debug!(
            "loading rp secrets with prefix: {}",
            self.rp_secret_id_prefix
        );
        let mut rp_materials = HashMap::new();
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
                        tracing::debug!("loaded secret for rp_id: {}", rp_secret.rp_id);
                        rp_materials.insert(rp_secret.rp_id, rp_secret.into());
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
        Ok(RpMaterialStore::new(rp_materials))
    }

    /// Stores a new DLog share for an RP in AWS Secrets Manager.
    ///
    /// Creates a new secret with the configured prefix and RP ID.
    #[instrument(level = "info", skip_all)]
    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()> {
        let StoreDLogShare {
            rp_id,
            public_key,
            rp_nullifier_key,
            share,
        } = store;
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, rp_id);
        let secret = AwsRpSecret::new(rp_id, public_key, rp_nullifier_key, share);
        self.client
            .create_secret()
            .name(secret_id)
            .secret_string(serde_json::to_string(&secret).expect("can serialize"))
            .send()
            .await
            .context("while creating secret")?;
        tracing::info!("created new rp secret for {rp_id}");
        Ok(())
    }

    /// Removes an RP's secret from AWS Secrets Manager.
    ///
    /// Permanently deletes the secret without recovery period.
    #[instrument(level = "info", skip(self))]
    async fn remove_dlog_share(&self, rp_id: RpId) -> eyre::Result<()> {
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, rp_id);
        self.client
            .delete_secret()
            .secret_id(secret_id)
            .force_delete_without_recovery(true)
            .send()
            .await
            .context("while deleting DLog Share")?;
        tracing::info!("deleted secret from AWS {rp_id}");
        Ok(())
    }

    /// Updates an RP's secret with a new epoch.
    ///
    /// Loads the existing secret, moves the current epoch to previous,
    /// and stores the new share as the current epoch.
    #[instrument(level = "info", skip(self, share))]
    async fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()> {
        // Load old secret to preserve previous epoch
        let secret_id = to_rp_secret_id(&self.rp_secret_id_prefix, rp_id);
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
            "updated rp secret for {rp_id} with current: {epoch}, previous: {prev_epoch}"
        );
        Ok(())
    }
}

/// Constructs the full secret ID for an RP in AWS Secrets Manager.
///
/// Combines the prefix with the RP ID.
#[inline(always)]
fn to_rp_secret_id(rp_secret_id_prefix: &str, rp: RpId) -> String {
    format!("{}/{}", rp_secret_id_prefix, rp.into_inner())
}
