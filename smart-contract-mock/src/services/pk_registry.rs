use std::{array, collections::BTreeMap, sync::Arc, time::Duration};

use oprf_types::{MerkleEpoch, MerkleRoot, sc_mock::MerkleRootUpdate};
use parking_lot::Mutex;
use rand::Rng;
use tokio::sync::broadcast;

use crate::{config::SmartContractMockConfig, merkle::MerkleTree};

#[derive(Clone)]
pub(crate) struct PublicKeyRegistry {
    config: Arc<SmartContractMockConfig>,
    storage: Arc<Mutex<RootStorage>>,
    bus: broadcast::Sender<MerkleRootUpdate>,
}

struct RootStorage {
    tree: MerkleTree,
    current_epoch: MerkleEpoch,
    roots: BTreeMap<MerkleEpoch, MerkleRoot>,
}

pub struct PublicKey {
    pub(crate) elements: [ark_babyjubjub::EdwardsAffine; 7],
}

impl PublicKey {
    pub fn random<R: Rng>(r: &mut R) -> Self {
        Self {
            elements: array::from_fn(|_| r.r#gen()),
        }
    }
}

impl PublicKeyRegistry {
    pub(crate) fn with_random_elements<R: Rng>(
        config: Arc<SmartContractMockConfig>,
        r: &mut R,
    ) -> Self {
        // Create a tree with the initial size
        let tree = MerkleTree::random(config.init_registry_size, r);
        // fairly arbitrary channel size
        let (tx, _) = broadcast::channel(4096);

        let registry = Self {
            storage: Arc::new(Mutex::new(RootStorage {
                tree,
                current_epoch: MerkleEpoch::new(config.init_registry_size as u128),
                roots: BTreeMap::new(),
            })),
            config,
            bus: tx,
        };

        // Now add some more hashes to have a cache of root stores
        for _ in 0..50 {
            registry.add_pk(PublicKey::random(r));
        }
        registry
    }

    pub(crate) fn subscribe_updates(&self) -> broadcast::Receiver<MerkleRootUpdate> {
        self.bus.subscribe()
    }

    pub(crate) fn start_add_pk_task(&self, interval: Duration) {
        let mut interval = tokio::time::interval(interval);
        let registry = self.clone();
        tokio::task::spawn(async move {
            loop {
                interval.tick().await;
                tracing::trace!("adding new pk..");
                registry.add_pk(PublicKey::random(&mut rand::thread_rng()));
            }
        });
    }

    pub(crate) fn add_pk(&self, pk: PublicKey) {
        let new_root = {
            let mut storage = self.storage.lock();
            storage.tree.push_leaf(pk);
            let new_epoch = storage.current_epoch.inc();
            let root = storage.tree.root();
            // add to cache
            storage.roots.insert(new_epoch, root);
            if storage.roots.len() > self.config.max_root_cache_size {
                storage.roots.pop_first();
            }
            MerkleRootUpdate {
                hash: root,
                epoch: storage.current_epoch,
            }
        };
        match self.bus.send(new_root) {
            Ok(listeners) => tracing::trace!("send new root to {listeners} subscribers"),
            Err(_) => tracing::trace!("no subscriber listening"),
        }
    }

    pub(crate) fn get_by_epoch(&self, epoch: MerkleEpoch) -> Option<MerkleRoot> {
        self.storage.lock().roots.get(&epoch).copied()
    }

    pub(crate) fn fetch_roots(&self, amount: u32) -> Vec<MerkleRootUpdate> {
        self.storage
            .lock()
            .roots
            .iter()
            .take(amount as usize)
            .map(|(k, v)| MerkleRootUpdate {
                epoch: *k,
                hash: *v,
            })
            .collect()
    }
}
