use std::{array, collections::VecDeque, sync::Arc, time::Duration};

use oprf_types::MerkleRoot;
use parking_lot::Mutex;
use rand::Rng;
use tokio::sync::broadcast;

use crate::{config::SmartContractMockConfig, merkle::MerkleTree};

#[derive(Clone)]
pub(crate) struct PublicKeyRegistry {
    config: Arc<SmartContractMockConfig>,
    storage: Arc<Mutex<RootStorage>>,
    bus: broadcast::Sender<MerkleRoot>,
}

struct RootStorage {
    tree: MerkleTree,
    roots: VecDeque<MerkleRoot>,
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
        let mut roots = VecDeque::new();
        // Create a tree with the initial size
        let mut tree = MerkleTree::random(config.init_registry_size, r);
        // Now add some more hashes to have a cache of root stores
        for _ in 0..50 {
            tree.push_leaf(PublicKey::random(r));
            add_to_root_store(&mut roots, tree.root(), config.max_root_cache_size);
        }
        // fairly arbitrary channel size
        let (tx, _) = broadcast::channel(4096);
        Self {
            config,
            storage: Arc::new(Mutex::new(RootStorage { tree, roots })),
            bus: tx,
        }
    }

    pub(crate) fn subscribe_updates(&self) -> broadcast::Receiver<MerkleRoot> {
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
            let root = storage.tree.root();
            add_to_root_store(&mut storage.roots, root, self.config.max_root_cache_size);
            root
        };
        match self.bus.send(new_root) {
            Ok(listeners) => tracing::trace!("send new root to {listeners} subscribers"),
            Err(_) => tracing::trace!("no subscriber listening"),
        }
    }

    pub(crate) fn is_valid_root(&self, root: MerkleRoot) -> bool {
        self.storage.lock().roots.contains(&root)
    }
    pub(crate) fn fetch_roots(&self, amount: u32) -> Vec<MerkleRoot> {
        self.storage
            .lock()
            .roots
            .iter()
            .take(amount as usize)
            .cloned()
            .collect()
    }
}

fn add_to_root_store(roots: &mut VecDeque<MerkleRoot>, new_root: MerkleRoot, max_length: usize) {
    roots.push_front(new_root);
    if roots.len() > max_length {
        roots.pop_back();
    }
}
