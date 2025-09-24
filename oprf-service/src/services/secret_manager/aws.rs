use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use eyre::{Context, ContextCompat};
use oprf_types::{RpId, ShareEpoch};
use serde::{Deserialize, Serialize};
use tokio::runtime::{self, Handle};
use tracing::instrument;

use crate::services::crypto_device::dlog_storage::RpMaterial;
use crate::{
    config::OprfPeerConfig,
    services::secret_manager::{DLogShare, PeerPrivateKey, SecretManager},
};

/// AWS Secret Manager client wrapper.
#[derive(Debug, Clone)]
pub(crate) struct AwsSecretManager {
    client: aws_sdk_secretsmanager::Client,
    config: Arc<OprfPeerConfig>,
    // holds a handle of the runtime to have the store/update be sync interface.
    runtime: runtime::Handle,
}

impl AwsSecretManager {
    /// Initializes an AWS secret manager client.
    ///
    /// Loads AWS configuration from the environment and wraps the client
    /// in a `SecretManagerService`.
    pub(crate) async fn init(config: Arc<OprfPeerConfig>) -> Self {
        // loads the latest defaults for aws
        tracing::info!("initializing AWS secret manager from env...");
        let aws_config = aws_config::load_from_env().await;
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        AwsSecretManager {
            client,
            config,
            runtime: Handle::current(),
        }
    }
}

/// JSON structure used to serialize secrets in AWS.
///
/// Stores the current and optionally previous epoch.
#[derive(Serialize, Deserialize)]
struct AwsSecret {
    rp_id: RpId,
    rp_public: k256::PublicKey,
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

impl AwsSecret {
    /// Creates a new secret for a given `RpId`.
    ///
    /// Current epoch is set to 0, previous is `None`.
    fn new(rp_id: RpId, rp_public: k256::PublicKey, secret: DLogShare) -> Self {
        Self {
            rp_id,
            rp_public,
            current: EpochSecret {
                epoch: ShareEpoch::default(),
                secret,
            },
            previous: None,
        }
    }
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(
        &self,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<(PeerPrivateKey, HashMap<RpId, RpMaterial>)> {
        tracing::info!(
            "loading secret key from AWS with name {}...",
            self.config.private_key_secret_id
        );
        let private_key = self
            .client
            .get_secret_value()
            .secret_id(self.config.private_key_secret_id.clone())
            .send()
            .await
            .context("while retrieving secret key")?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("cannot find secret with provided name"))?
            .to_owned();
        let private_key = ark_babyjubjub::Fr::from_str(&private_key)
            .map_err(|_| eyre::eyre!("Cannot parse private key from AWS"))?;
        let private_key = PeerPrivateKey::from(private_key);
        tracing::info!("loading {} RP secrets..", rp_ids.len());
        let amount_rps = rp_ids.len();
        let rp_ids = rp_ids
            .into_iter()
            .map(|rp_id| to_secret_id(&self.config, rp_id))
            .collect::<Vec<_>>();

        let mut shares = HashMap::with_capacity(rp_ids.len());
        let mut stream = self
            .client
            .batch_get_secret_value()
            .set_secret_id_list(Some(rp_ids))
            .into_paginator()
            .send();
        tracing::debug!("reading batch result...");
        while let Some(batch_result) = stream.next().await {
            tracing::debug!("got batch..");
            let batch_result = batch_result.context("while loading DLog shares")?;
            if batch_result.errors.as_ref().is_some_and(|e| !e.is_empty()) {
                let error = batch_result
                    .errors()
                    .first()
                    .expect("checked that there is an error");
                eyre::bail!(format!(
                    "Cannot retrieve {:?}, because {:?}:{:?}",
                    error.secret_id, error.error_code, error.message
                ));
            }
            let secret_values = batch_result
                .secret_values
                .ok_or_else(|| eyre::eyre!("Secret Values is none in batch retrieve"))?;
            tracing::debug!("batch size: {}", secret_values.len());
            for secret_id in secret_values {
                let aws_secret: AwsSecret =
                    serde_json::from_str(secret_id.secret_string().context("Not a secret string")?)
                        .context("cannot deser AWS Secret")?;
                let _guard =
                    tracing::debug_span!("parse secret", rp_id = %aws_secret.rp_id).entered();
                tracing::debug!(
                    "loaded current epoch: {}, previous epoch {:?}",
                    aws_secret.current.epoch,
                    aws_secret.previous.as_ref().map(|p| p.epoch.to_string())
                );
                let mut rp_shares = HashMap::new();
                rp_shares.insert(aws_secret.current.epoch, aws_secret.current.secret);
                if let Some(previous) = aws_secret.previous {
                    rp_shares.insert(previous.epoch, previous.secret);
                }
                shares.insert(
                    aws_secret.rp_id,
                    RpMaterial::new(rp_shares, aws_secret.rp_public.into()),
                );
            }
        }

        if shares.len() != amount_rps {
            eyre::bail!(
                "Expected {amount_rps} secrets, but could only load {}",
                shares.len()
            );
        }
        Ok((private_key, shares))
    }

    #[instrument(level = "info", skip(self, share))]
    fn store_dlog_share(
        &self,
        rp_id: RpId,
        pubic_key: k256::PublicKey,
        share: DLogShare,
    ) -> eyre::Result<()> {
        let secret_id = to_secret_id(&self.config, rp_id);
        tracing::info!("creating new secret at AWS: {secret_id}");
        let secret = AwsSecret::new(rp_id, pubic_key, share);
        let create_fut = self
            .client
            .create_secret()
            .name(secret_id)
            .secret_string(serde_json::to_string(&secret).expect("can serialize"))
            .send();
        self.runtime
            .block_on(create_fut)
            .context("while creating secret")?;
        tracing::debug!("success");
        Ok(())
    }

    #[instrument(level = "info", skip(self, share))]
    fn update_dlog_share(
        &self,
        rp_id: RpId,
        epoch: ShareEpoch,
        share: DLogShare,
    ) -> eyre::Result<()> {
        // Load old secret to preserve previous epoch
        let secret_id = to_secret_id(&self.config, rp_id);
        tracing::info!("loading old secret first at {secret_id}");
        let send_fut = self
            .client
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send();
        let secret_value = self
            .runtime
            .block_on(send_fut)
            .context("while loading old secret")?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("cannot find secret with provided name"))?
            .to_owned();

        let mut aws_secret: AwsSecret =
            serde_json::from_str(&secret_value).context("Cannot deserialize AWS Secret")?;

        let prev_epoch = aws_secret.current.epoch;

        aws_secret.previous = Some(aws_secret.current.clone());
        aws_secret.current = EpochSecret {
            epoch,
            secret: share,
        };

        tracing::info!("Put new secret value with current: {epoch}, previous: {prev_epoch}");
        let put_fut = self
            .client
            .put_secret_value()
            .secret_id(secret_id)
            .secret_string(serde_json::to_string(&aws_secret).expect("can serialize"))
            .send();
        self.runtime
            .block_on(put_fut)
            .context("while storing new secret")?;
        tracing::debug!("success");
        Ok(())
    }
}

#[inline(always)]
fn to_secret_id(config: &OprfPeerConfig, rp: RpId) -> String {
    format!("{}/{}", config.dlog_share_secret_id_suffix, rp.into_inner())
}
