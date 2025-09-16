use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use eyre::{Context, ContextCompat};
use oprf_types::{KeyEpoch, RpId};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    config::OprfConfig,
    services::secret_manager::{DLogShare, PrivateKey, SecretManager, SecretManagerService},
};

/// Type alias for secret manager client for ergonomics
pub(crate) type AwsSecretManager = aws_sdk_secretsmanager::Client;

/// We store the shares as Json because the secret manager API is rather clunky to use.
/// If someone has the patience to build the AWS secret manager with only native API support remove this struct, but for now we simply use this struct at application level to retrieve current and previous epoch.
#[derive(Serialize, Deserialize)]
struct AwsSecret {
    rp_id: RpId,
    current: EpochSecret,
    // Is none for first secret
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: Option<EpochSecret>,
}

/// The secret associated with an epoch
#[derive(Clone, Serialize, Deserialize)]
struct EpochSecret {
    epoch: KeyEpoch,
    secret: DLogShare,
}

impl AwsSecret {
    /// Creates a new secret to serialize and send to AWS Secret Manager.
    /// Note on serializations:
    /// * Sets previous to `None`
    /// * Sets Current epoch to 0.
    #[expect(dead_code)]
    fn new(rp_id: RpId, secret: DLogShare) -> Self {
        Self {
            rp_id,
            current: EpochSecret {
                epoch: KeyEpoch::default(),
                secret,
            },
            previous: None,
        }
    }
}

/// Creates a new instance of the AWS secret manager. Loads the aws config from the environment with defaults from latest version.
pub(crate) async fn init() -> SecretManagerService {
    // loads the latest defaults for aws
    tracing::info!("initializing AWS secret manager from env...");
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    // this internally has another Arc but it is what it is
    Arc::new(client)
}

#[async_trait]
impl SecretManager for AwsSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(
        &self,
        config: &OprfConfig,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<(PrivateKey, HashMap<RpId, HashMap<KeyEpoch, DLogShare>>)> {
        tracing::info!(
            "loading secret key from AWS with name {}...",
            config.private_key_secret_id
        );
        let private_key = self
            .get_secret_value()
            .secret_id(config.private_key_secret_id.clone())
            .send()
            .await
            .context("while retrieving secret key")?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("cannot find secret with provided name"))?
            .to_owned();
        let private_key = ark_babyjubjub::Fr::from_str(&private_key)
            .map_err(|_| eyre::eyre!("Cannot parse private key from AWS"))?;
        let private_key = PrivateKey::from(private_key);
        tracing::info!("loading {} RP secrets..", rp_ids.len());
        let amount_rps = rp_ids.len();
        let rp_ids = rp_ids.into_iter().map(to_secret_id).collect::<Vec<_>>();

        let mut shares = HashMap::with_capacity(rp_ids.len());
        let mut stream = self
            .batch_get_secret_value()
            .set_secret_id_list(Some(rp_ids))
            .into_paginator()
            .send();
        tracing::debug!("reading batch result...");
        while let Some(batch_result) = stream.next().await {
            tracing::debug!("got batch..");
            let batch_result = batch_result.context("while loading DLog shares")?;
            if batch_result.errors.is_some() {
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
                shares.insert(aws_secret.rp_id, rp_shares);
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
    async fn create_dlog_share(&self, rp_id: RpId, share: DLogShare) -> eyre::Result<()> {
        tracing::info!("creating new secret at AWS");
        let secret = AwsSecret::new(rp_id, share);
        self.create_secret()
            .name(to_secret_id(rp_id))
            .secret_string(serde_json::to_string(&secret).expect("can serialize"))
            .send()
            .await
            .context("while creating secret")?;
        tracing::debug!("success");
        Ok(())
    }

    #[instrument(level = "info", skip(self, share))]
    async fn store_dlog_share(
        &self,
        rp_id: RpId,
        epoch: KeyEpoch,
        share: DLogShare,
    ) -> eyre::Result<()> {
        // load the old secret to obtain information to build AWSSecret
        let secret_id = to_secret_id(rp_id);
        tracing::info!("loading old secret first at {secret_id}");
        let secret_value = self
            .get_secret_value()
            .secret_id(secret_id.clone())
            .send()
            .await
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
        self.put_secret_value()
            .secret_id(secret_id)
            .secret_string(serde_json::to_string(&aws_secret).expect("can serialize"))
            .send()
            .await
            .context("while storing new secret")?;
        tracing::debug!("success");
        Ok(())
    }
}

#[inline(always)]
fn to_secret_id(rp: RpId) -> String {
    format!("oprf::rp::{}", rp)
}
