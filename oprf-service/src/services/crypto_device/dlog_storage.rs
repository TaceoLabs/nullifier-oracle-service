//! Helper storage for DLog secret shares.
//!
//! This module provides [`DLogShareStorage`], which securely holds the
//! secret shares for each relying-party and epoch.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for shared ownership.

use std::{collections::HashMap, sync::Arc};

use oprf_types::{RpId, ShareEpoch, api::v1::NullifierShareIdentifier};
use parking_lot::RwLock;

use crate::services::crypto_device::DLogShare;

/// Thread-safe storage for DLog secret shares.
///
/// Maps each `RpId` to a map of `ShareEpoch` → `DLogShare`.  
/// Provides methods to retrieve or add shares while maintaining safety.
#[derive(Clone)]
pub(super) struct DLogShareStorage(Arc<RwLock<HashMap<RpId, HashMap<ShareEpoch, DLogShare>>>>);

impl DLogShareStorage {
    /// Creates a new storage instance with the provided initial shares.
    pub(super) fn new(inner: HashMap<RpId, HashMap<ShareEpoch, DLogShare>>) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Retrieves the secret share for the given [`NullifierShareIdentifier`].
    ///
    /// Returns `None` if the RP or share epoch is not found.
    pub(super) fn get(
        &self,
        key_identifier: &NullifierShareIdentifier,
    ) -> Option<ark_babyjubjub::Fr> {
        self.0
            .read()
            .get(&key_identifier.rp_id)?
            .get(&key_identifier.key_epoch)
            .map(|share| share.0)
    }

    /// Adds a new secret share for the given `RpId` with epoch 0.
    ///
    /// Overwrites any existing entry.  
    /// Intended for creating new shares, not rotation.
    pub(super) fn add(&self, rp_id: RpId, dlog_share: DLogShare) {
        let mut shares = HashMap::new();
        shares.insert(ShareEpoch::new(), dlog_share);
        if self.0.write().insert(rp_id, shares).is_some() {
            tracing::warn!("overwriting share for {rp_id}");
        }
    }
}
