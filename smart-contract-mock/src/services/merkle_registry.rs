use std::str::FromStr;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ark_ec::{AdditiveGroup as _, AffineRepr as _};
use oprf_types::crypto::UserPublicKeyBatch;
use oprf_types::sc_mock::MerklePath;
use oprf_types::{MerkleEpoch, MerkleRoot, sc_mock::MerkleRootUpdate};
use parking_lot::Mutex;
use poseidon2::Poseidon2;
use rand::Rng;
use tokio::sync::broadcast;

use crate::config::SmartContractMockConfig;

#[derive(Clone)]
pub(crate) struct MerkleRootRegistry {
    config: Arc<SmartContractMockConfig>,
    storage: Arc<Mutex<BTreeMap<MerkleEpoch, MerklePath>>>,
    current_index: Arc<AtomicU64>,
    bus: broadcast::Sender<MerkleRootUpdate>,
}

struct PoseidonCompression {
    poseidon2_2: Poseidon2<ark_babyjubjub::Fq, 2, 5>,
    poseidon2_16: Poseidon2<ark_babyjubjub::Fq, 16, 5>,
    domain_separator: ark_babyjubjub::Fq,
}
impl PoseidonCompression {
    fn merkle_leaf(&self, pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
        let mut input = [ark_babyjubjub::Fq::ZERO; 16];
        input[0] = self.domain_separator;
        for i in 0..7 {
            input[i * 2 + 1] = pk.values[i].x().expect("not infinity");
            input[i * 2 + 2] = pk.values[i].y().expect("not infinity");
        }
        self.poseidon2_16.permutation(&input)[1]
    }

    fn hash_children(
        &self,
        left: ark_babyjubjub::Fq,
        right: ark_babyjubjub::Fq,
    ) -> ark_babyjubjub::Fq {
        self.poseidon2_2.permutation(&[left, right])[0] + left
    }
}

impl Default for PoseidonCompression {
    fn default() -> Self {
        Self {
            poseidon2_2: Default::default(),
            poseidon2_16: Default::default(),
            domain_separator: ark_babyjubjub::Fq::from_str("105702839725298824521994315")
                .expect("works"),
        }
    }
}

impl MerkleRootRegistry {
    pub(crate) fn with_random_elements<R: Rng>(
        config: Arc<SmartContractMockConfig>,
        r: &mut R,
    ) -> Self {
        let max_cache_size = config.max_root_cache_size;
        // fairly arbitrary channel size
        let (tx, _) = broadcast::channel(4096);
        // this is just a mock of a merkle tree - we just produce random paths and return those for testing
        let registry = MerkleRootRegistry {
            config,
            storage: Arc::new(Mutex::new(BTreeMap::new())),
            current_index: Arc::new(AtomicU64::default()),
            bus: tx,
        };
        tracing::debug!("filling root cache (size={})", max_cache_size);
        for _ in 0..max_cache_size {
            registry.add_random(r);
        }
        registry
    }

    // Creates a path where the key is the leave and the path are random siblings.
    pub(crate) fn add_random<R: Rng>(&self, r: &mut R) {
        let key = UserPublicKeyBatch::random(r);
        self.add_public_key(key, r);
    }

    pub(crate) fn add_public_key<R: Rng>(
        &self,
        key_batch: UserPublicKeyBatch,
        r: &mut R,
    ) -> (MerkleEpoch, MerklePath) {
        let index = self.current_index.fetch_add(1, Ordering::Relaxed);
        let poseidon = PoseidonCompression::default();
        let mut current = poseidon.merkle_leaf(&key_batch);
        let mut siblings = Vec::new();
        // some random siblings
        for level in 0..self.config.merkle_depth {
            let sibling = r.r#gen();
            siblings.push(sibling);
            let bit = (index >> level) & 1;
            if bit == 0 {
                current = poseidon.hash_children(current, sibling);
            } else {
                current = poseidon.hash_children(sibling, current);
            }
        }
        let root = MerkleRoot::from(current);
        let epoch = MerkleEpoch::from(index);
        let path = MerklePath {
            index,
            siblings,
            root: MerkleRoot::from(current),
            key_batch,
        };
        self.storage.lock().insert(epoch, path.clone());
        // write update
        match self.bus.send(MerkleRootUpdate { hash: root, epoch }) {
            Ok(listeners) => tracing::trace!("send new root to {listeners} subscribers"),
            Err(_) => tracing::trace!("no subscriber listening"),
        }
        (epoch, path)
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
                registry.add_random(&mut rand::thread_rng());
            }
        });
    }

    pub(crate) fn get_by_epoch(&self, epoch: MerkleEpoch) -> Option<MerkleRoot> {
        self.storage.lock().get(&epoch).map(|x| x.root)
    }

    // fetches the latest `amount` roots.
    pub(crate) fn fetch_roots(&self, amount: u32) -> Vec<MerkleRootUpdate> {
        self.storage
            .lock()
            .iter()
            .rev()
            .take(amount as usize)
            .map(|(k, v)| MerkleRootUpdate {
                epoch: *k,
                hash: v.root,
            })
            .collect()
    }
}
