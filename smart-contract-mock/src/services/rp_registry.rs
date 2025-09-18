use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oprf_types::RpId;

#[derive(Clone)]
pub(crate) struct RpRegistry(Arc<Mutex<HashMap<RpId, ark_babyjubjub::EdwardsAffine>>>);

impl RpRegistry {
    pub(crate) fn init() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn get_public_key(&self, rp_id: RpId) -> Option<ark_babyjubjub::EdwardsAffine> {
        self.0.lock().expect("not poisoned").get(&rp_id).cloned()
    }

    pub(crate) fn add_public_key(&self, rp_id: RpId, pk: ark_babyjubjub::EdwardsAffine) {
        let removed = self.0.lock().expect("not poisoned").insert(rp_id, pk);
        if removed.is_some() {
            tracing::error!("There was already a key for {rp_id} - removed old key");
        }
    }
}
