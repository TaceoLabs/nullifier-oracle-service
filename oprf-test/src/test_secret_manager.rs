use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use itertools::Itertools;
use oprf_service::{DLogShare, RpMaterialStore, SecretManager, StoreDLogShare};
use oprf_types::{RpId, ShareEpoch};
use parking_lot::Mutex;
use secrecy::SecretString;

#[derive(Clone)]
pub struct TestSecretManager {
    wallet_private_key: String,
    store: Arc<Mutex<HashSet<RpId>>>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: String) -> Self {
        Self {
            wallet_private_key,
            store: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn load_rps(&self) -> Vec<RpId> {
        self.store.lock().iter().copied().collect_vec()
    }
}

#[async_trait]
impl SecretManager for TestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<SecretString> {
        Ok(SecretString::from(self.wallet_private_key.clone()))
    }
    async fn load_secrets(&self) -> eyre::Result<RpMaterialStore> {
        Ok(RpMaterialStore::default())
    }

    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()> {
        let StoreDLogShare {
            rp_id,
            public_key: _,
            rp_nullifier_key: _,
            share: _,
        } = store;
        self.store.lock().insert(rp_id);
        Ok(())
    }

    async fn remove_dlog_share(&self, rp_id: RpId) -> eyre::Result<()> {
        if !self.store.lock().remove(&rp_id) {
            panic!("trying to remove rp id that does not exist");
        }
        Ok(())
    }

    async fn update_dlog_share(&self, _: RpId, _: ShareEpoch, _: DLogShare) -> eyre::Result<()> {
        unreachable!()
    }
}
