use std::{collections::HashMap, sync::Arc};

use oprf_types::{RpId, sc_mock::RpKeys};
use parking_lot::Mutex;
use tracing::instrument;

#[derive(Clone)]
pub(crate) struct RpRegistry(Arc<Mutex<HashMap<RpId, RpKeys>>>);

impl RpRegistry {
    pub(crate) fn init() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn list_public_keys(&self) -> Vec<RpId> {
        self.0.lock().keys().cloned().collect()
    }

    pub(crate) fn get_public_key(&self, rp_id: RpId) -> Option<RpKeys> {
        self.0.lock().get(&rp_id).cloned()
    }

    #[instrument(level = "info", skip(self, keys))]
    pub(crate) fn add_public_key(&self, rp_id: RpId, keys: RpKeys) {
        tracing::info!("adding nullifier PK: {}", keys.nullifier);
        let removed = self.0.lock().insert(rp_id, keys);
        if removed.is_some() {
            tracing::error!("There was already a key for {rp_id} - removed old key");
        }
    }
}
