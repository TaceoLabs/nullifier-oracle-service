use std::fs::File;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{RpId, ShareEpoch};
use tracing::instrument;

use crate::config::OprfPeerConfig;
use crate::services::crypto_device::PeerPrivateKey;
use crate::services::secret_manager::{DLogShare, SecretManager, SecretManagerService};

/// Type alias for secret manager client for ergonomics
pub(crate) struct LocalSecretManager;

/// Creates a new instance of the AWS secret manager. Loads the aws config from the environment with defaults from latest version.
pub(crate) fn init(config: &OprfPeerConfig) -> eyre::Result<SecretManagerService> {
    config.environment.assert_is_dev();
    Ok(Arc::new(LocalSecretManager))
}

#[async_trait]
impl SecretManager for LocalSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(
        &self,
        _rp_ids: Vec<RpId>,
    ) -> eyre::Result<(
        PeerPrivateKey,
        HashMap<RpId, HashMap<ShareEpoch, DLogShare>>,
    )> {
        todo!()
        // let key_share =
        //     serde_json::from_reader::<_, DLogShare>(File::open(&config.private_key_secret_id)?)?;
        // let private_key = PeerPrivateKey::from(ark_babyjubjub::Fr::default());
        // let key_shares = HashMap::from([(ShareEpoch::default(), key_share)]);
        // let rp_key_shares = HashMap::from([(RpId::new(0), key_shares)]);
        // Ok((private_key, rp_key_shares))
    }

    #[instrument(level = "info", skip(self, _share))]
    fn store_dlog_share(&self, _rp_id: RpId, _share: DLogShare) -> eyre::Result<()> {
        Ok(())
    }

    #[instrument(level = "info", skip(self, _share))]
    fn update_dlog_share(
        &self,
        _rp_id: RpId,
        _epoch: ShareEpoch,
        _share: DLogShare,
    ) -> eyre::Result<()> {
        Ok(())
    }
}
