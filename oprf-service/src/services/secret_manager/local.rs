use std::fs::File;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{KeyEpoch, RpId};
use tracing::instrument;

use crate::{
    config::OprfConfig,
    services::secret_manager::{DLogShare, PrivateKey, SecretManager, SecretManagerService},
};

/// Type alias for secret manager client for ergonomics
pub(crate) struct LocalSecretManager;

/// Creates a new instance of the AWS secret manager. Loads the aws config from the environment with defaults from latest version.
pub(crate) fn init() -> eyre::Result<SecretManagerService> {
    Ok(Arc::new(LocalSecretManager))
}

#[async_trait]
impl SecretManager for LocalSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(
        &self,
        config: &OprfConfig,
        _rp_ids: Vec<RpId>,
    ) -> eyre::Result<(PrivateKey, HashMap<RpId, HashMap<KeyEpoch, DLogShare>>)> {
        let key_share =
            serde_json::from_reader::<_, DLogShare>(File::open(&config.private_key_share_path)?)?;
        let private_key = PrivateKey::from(ark_babyjubjub::Fr::default());
        let key_shares = HashMap::from([(KeyEpoch::default(), key_share)]);
        let rp_key_shares = HashMap::from([(RpId::new(0), key_shares)]);
        Ok((private_key, rp_key_shares))
    }

    #[instrument(level = "info", skip(self, _share))]
    async fn create_dlog_share(&self, _rp_id: RpId, _share: DLogShare) -> eyre::Result<()> {
        Ok(())
    }

    #[instrument(level = "info", skip(self, _share))]
    async fn store_dlog_share(
        &self,
        _rp_id: RpId,
        _epoch: KeyEpoch,
        _share: DLogShare,
    ) -> eyre::Result<()> {
        Ok(())
    }
}
