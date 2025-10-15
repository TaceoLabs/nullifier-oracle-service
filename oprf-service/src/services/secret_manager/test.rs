use std::collections::HashMap;

use async_trait::async_trait;
use oprf_types::crypto::RpNullifierKey;
use oprf_types::{RpId, ShareEpoch};
use parking_lot::Mutex;
use tracing::instrument;

use crate::services::crypto_device::PeerPrivateKey;
use crate::services::crypto_device::dlog_storage::RpMaterial;
use crate::services::secret_manager::{DLogShare, SecretManager};

/// Type alias for secret manager client for ergonomics
pub(crate) struct TestSecretManager {
    private_key: PeerPrivateKey,
    pub(crate) rp_materials: Mutex<HashMap<RpId, RpMaterial>>,
}

impl TestSecretManager {
    pub(crate) fn new(private_key: PeerPrivateKey, shares: HashMap<RpId, RpMaterial>) -> Self {
        Self {
            private_key,
            rp_materials: Mutex::new(shares),
        }
    }
}

#[async_trait]
impl SecretManager for TestSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<(PeerPrivateKey, HashMap<RpId, RpMaterial>)> {
        Ok((self.private_key.clone(), self.rp_materials.lock().clone()))
    }

    #[instrument(level = "info", skip(self, share))]
    async fn store_dlog_share(
        &self,
        rp_id: RpId,
        public_key: k256::PublicKey,
        rp_nullifier_key: RpNullifierKey,
        share: DLogShare,
    ) -> eyre::Result<()> {
        self.rp_materials
            .lock()
            .entry(rp_id)
            .or_insert(RpMaterial::new(
                HashMap::new(),
                public_key.into(),
                rp_nullifier_key,
            ))
            .shares
            .insert(ShareEpoch::default(), share);
        Ok(())
    }

    #[instrument(level = "info", skip(self, _share))]
    async fn update_dlog_share(
        &self,
        _rp_id: RpId,
        _epoch: ShareEpoch,
        _share: DLogShare,
    ) -> eyre::Result<()> {
        Ok(())
    }
}
