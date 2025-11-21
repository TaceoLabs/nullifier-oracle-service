use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use itertools::Itertools;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_service::{OprfKeyMaterialStore, SecretManager, StoreDLogShare};
use oprf_types::{OprfKeyId, ShareEpoch};
use parking_lot::Mutex;
use secrecy::SecretString;

#[derive(Clone)]
pub struct TestSecretManager {
    wallet_private_key: String,
    store: Arc<Mutex<HashSet<OprfKeyId>>>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: String) -> Self {
        Self {
            wallet_private_key,
            store: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn load_oprf_pks(&self) -> Vec<OprfKeyId> {
        self.store.lock().iter().copied().collect_vec()
    }
}

#[async_trait]
impl SecretManager for TestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<SecretString> {
        Ok(SecretString::from(self.wallet_private_key.clone()))
    }
    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore> {
        Ok(OprfKeyMaterialStore::default())
    }

    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()> {
        let StoreDLogShare {
            oprf_key_id,
            oprf_public_key: _,
            share: _,
        } = store;
        self.store.lock().insert(oprf_key_id);
        Ok(())
    }

    async fn remove_dlog_share(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        if !self.store.lock().remove(&oprf_key_id) {
            panic!("trying to remove rp id that does not exist");
        }
        Ok(())
    }

    async fn update_dlog_share(
        &self,
        _: OprfKeyId,
        _: ShareEpoch,
        _: DLogShareShamir,
    ) -> eyre::Result<()> {
        unreachable!()
    }
}
