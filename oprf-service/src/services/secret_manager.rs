use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use oprf_types::{KeyEpoch, RpId};

use crate::{
    config::OprfConfig,
    services::crypto_device::{DLogShare, PrivateKey},
};

pub(crate) mod aws;

/// Dyn trait for the secret manager service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Trait that implementations of secret managers need to implement. Currently, we support the following secret managers:
/// - AWS
#[async_trait]
pub(crate) trait SecretManager {
    /// Initial call that loads the private key and all shares from the provided [`RpIds`](RpId).
    ///
    /// The private key is used to compute Diffie-Hellman with the Smart Contract.
    /// Every Rp has a dedicated DLog share and its share in turn has a dedicated epoch (how old it is). We load for every Rp provided as parameter at least the current epoch (current in the latest stored in the secret manager).
    ///
    /// Implementations should check that there is a share for every Rp and return error if not possible.
    async fn load_secrets(
        &self,
        config: &OprfConfig,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<(PrivateKey, HashMap<RpId, HashMap<KeyEpoch, DLogShare>>)>;

    /// Creates a new DLog share for the provided [`RpId`] with epoch 0.
    ///
    /// This method should only be called the first time an [`RpId`] creates a key. If you want to rotate the shares, use [`SecretManager::store_dlog_share`] instead.
    #[expect(dead_code)]
    async fn create_dlog_share(&self, rp_id: RpId, share: DLogShare) -> eyre::Result<()>;

    /// Updates a DLog share of [`RpId`] with the provided [`KeyEpoch`].
    ///
    /// Implementations may fail if the key epoch is already used. Check whether this is a valid epoch should be done at callsite.
    ///
    /// This method is used for updating existing key shares. Use [`SecretManager::create_dlog_share`] if you want to create a new secret.
    #[expect(dead_code)]
    async fn store_dlog_share(
        &self,
        rp_id: RpId,
        epoch: KeyEpoch,
        share: DLogShare,
    ) -> eyre::Result<()>;
}
