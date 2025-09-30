use std::{collections::HashMap, sync::Arc};

use oprf_types::{RpId, crypto::RpNullifierKey};
use parking_lot::Mutex;
use tracing::instrument;

#[derive(Clone)]
pub(crate) struct RpRegistry(Arc<Mutex<HashMap<RpId, RpMaterial>>>);

struct RpMaterial {
    nullifier_key: RpNullifierKey,
    rp_signing_key: k256::SecretKey,
}

impl RpRegistry {
    pub(crate) fn init() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn list_public_keys(&self) -> Vec<RpId> {
        self.0.lock().keys().cloned().collect()
    }

    pub(crate) fn get_public_key(&self, rp_id: RpId) -> Option<RpNullifierKey> {
        self.0
            .lock()
            .get(&rp_id)
            .map(|rp| rp.nullifier_key.to_owned())
    }

    pub(crate) fn signing_key(&self, rp_id: RpId) -> Option<k256::SecretKey> {
        self.0
            .lock()
            .get(&rp_id)
            .map(|rp| rp.rp_signing_key.to_owned())
    }

    #[instrument(level = "info", skip(self, nullifier_key, rp_signing_key))]
    pub(crate) fn add_public_key(
        &self,
        rp_id: RpId,
        nullifier_key: RpNullifierKey,
        rp_signing_key: k256::SecretKey,
    ) {
        tracing::info!("adding PK: {nullifier_key}");
        let removed = self.0.lock().insert(
            rp_id,
            RpMaterial {
                nullifier_key,
                rp_signing_key,
            },
        );
        if removed.is_some() {
            tracing::error!("There was already a key for {rp_id} - removed old key");
        }
    }
}
