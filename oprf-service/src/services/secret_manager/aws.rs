use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use eyre::Context;
use oprf_types::crypto::RpNullifierKey;
use oprf_types::{RpId, ShareEpoch};
use serde::{Deserialize, Serialize};
use tracing::instrument;

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
    pub(crate) async fn init(rp_secret_id_prefix: String) -> Self {
        // loads the latest defaults for aws
        tracing::info!("initializing AWS secret manager from env...");
        let aws_config = aws_config::load_from_env().await;
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

#[inline(always)]
fn to_rp_secret_id(rp_secret_id_prefix: &str, rp: RpId) -> String {
    format!("{}/{}", rp_secret_id_prefix, rp.into_inner())
}
