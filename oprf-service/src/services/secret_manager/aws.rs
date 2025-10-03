use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use eyre::Context;
use oprf_types::crypto::RpNullifierKey;
use oprf_types::{RpId, ShareEpoch};
use serde::{Deserialize, Serialize};
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
        AwsSecretManager { client, config }
    }
}

/// JSON structure used to serialize secrets in AWS.
///
/// Stores the current and optionally previous epoch.
#[derive(Serialize, Deserialize)]
struct AwsSecret {
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

impl AwsSecret {
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

#[async_trait]
impl SecretManager for AwsSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<(PeerPrivateKey, HashMap<RpId, RpMaterial>)> {
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

        // TODO how load old DLogShares
        // load via paginate
        Ok((private_key, HashMap::default()))
    }

    #[instrument(level = "info", skip(self, public_key, share))]
    async fn store_dlog_share(
        &self,
        rp_id: RpId,
        public_key: k256::PublicKey,
        rp_nullifier_key: RpNullifierKey,
        share: DLogShare,
    ) -> eyre::Result<()> {
        let secret_id = to_secret_id(&self.config, rp_id);
        tracing::info!("creating new secret at AWS: {secret_id}");
        let secret = AwsSecret::new(rp_id, public_key, rp_nullifier_key, share);
        self.client
            .create_secret()
            .name(secret_id)
            .secret_string(serde_json::to_string(&secret).expect("can serialize"))
            .send()
            .await
            .context("while creating secret")?;
        tracing::debug!("success");
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
        let secret_id = to_secret_id(&self.config, rp_id);
        tracing::info!("loading old secret first at {secret_id}");
        let secret_value = self
            .client
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
        self.client
            .put_secret_value()
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
fn to_secret_id(config: &OprfPeerConfig, rp: RpId) -> String {
    format!("{}/{}", config.dlog_share_secret_id_suffix, rp.into_inner())
}
