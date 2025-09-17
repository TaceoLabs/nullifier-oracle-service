use std::{collections::HashMap, sync::Arc};

use oprf_types::{RpId, crypto::RpNullifierKey};
use parking_lot::Mutex;
use tracing::instrument;

#[derive(Clone)]
pub(crate) struct RpRegistry(Arc<Mutex<HashMap<RpId, RpNullifierKey>>>);

impl RpRegistry {
    pub(crate) fn init() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn list_public_keys(&self) -> Vec<RpId> {
        self.0.lock().keys().cloned().collect()
    }

    pub(crate) fn get_public_key(&self, rp_id: RpId) -> Option<RpNullifierKey> {
        self.0.lock().get(&rp_id).cloned()
    }

    #[instrument(level = "info", skip(self, pk))]
    pub(crate) fn add_public_key(&self, rp_id: RpId, pk: RpNullifierKey) {
        tracing::info!("adding PK: {pk}");
        let removed = self.0.lock().insert(rp_id, pk);
        if removed.is_some() {
            tracing::error!("There was already a key for {rp_id} - removed old key");
        }
    }
}
