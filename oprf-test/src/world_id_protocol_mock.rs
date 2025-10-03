use std::{collections::HashSet, path::PathBuf, process::Command, sync::Arc};

use alloy::{
    primitives::{Address, U256},
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent as _,
};
use ark_ff::{AdditiveGroup as _, PrimeField as _};
use futures::StreamExt as _;
use oprf_client::{EdDSAPrivateKey, EdDSAPublicKey, UserKeyMaterial};
use oprf_types::crypto::UserPublicKeyBatch;
use poseidon2::{POSEIDON2_BN254_T2_PARAMS, Poseidon2};
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::{Branch, InclusionProof, imt::MerkleTree};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};

sol! {
    #[sol(rpc)]
    event AccountCreated(
        uint256 indexed accountIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256 offchainSignerCommitment
    );
}

struct PoseidonHasher;

impl Hasher for PoseidonHasher {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left = ark_bn254::Fr::from_le_bytes_mod_order(&left.to_le_bytes::<32>()[..]);
        let right = ark_bn254::Fr::from_le_bytes_mod_order(&right.to_le_bytes::<32>()[..]);
        let mut input = [left, right];
        let feed_forward = input[0];
        Poseidon2::new(&POSEIDON2_BN254_T2_PARAMS).permutation_in_place(&mut input);
        input[0] += feed_forward;
        U256::from_limbs(input[0].into_bigint().0)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedAccountCreated {
    pub account_index_hex: String,
    pub recovery_address_bytes: String,
    pub authenticator_addresses_hex: Vec<String>,
    pub offchain_signer_commitment_hex: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResponse {
    pub account_index: u64,
    pub leaf_index: u64,
    pub root: U256,
    pub proof: Vec<U256>,
}

impl ProofResponse {
    pub fn new(account_index: u64, leaf_index: u64, root: U256, proof: Vec<U256>) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
        }
    }
}

pub struct AuthTreeIndexer {
    _provider: DynProvider,
    tree: Arc<RwLock<MerkleTree<PoseidonHasher>>>,
    account_idx: mpsc::Receiver<u64>,
}

impl AuthTreeIndexer {
    pub async fn init(
        depth: usize,
        contract_address: &str,
        ws_rpc_url: &str,
    ) -> eyre::Result<Self> {
        tracing::info!("creating provider...");
        let tree = Arc::new(RwLock::new(MerkleTree::new(depth, U256::ZERO)));
        let accounts = Arc::new(RwLock::new(HashSet::new()));
        let tree_clone = Arc::clone(&tree);
        let accounts_clone = Arc::clone(&accounts);

        println!("creating provider...");
        let ws = WsConnect::new(ws_rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let contract_address: Address = contract_address.parse()?;

        let filter = Filter::new()
            .address(contract_address)
            .event_signature(AccountCreated::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();
        let (tx, rx) = mpsc::channel(1);
        println!("listening for events...");
        tokio::spawn(async move {
            while let Some(log) = stream.next().await {
                let account_created = decode_account_created(&log).expect("can decode");
                println!(
                    "got account_created account_index: {}",
                    account_created.account_index_hex
                );
                update_tree_with_event(&tree_clone, &accounts_clone, &account_created)
                    .await
                    .expect("can update tree");
                tx.send(hex_to_u64(&account_created.account_index_hex).expect("valid index"))
                    .await
                    .expect("can send");
            }
        });
        Ok(AuthTreeIndexer {
            _provider: provider.erased(),
            tree,
            account_idx: rx,
        })
    }

    pub async fn get_proof(&self, account_index: u64) -> eyre::Result<ProofResponse> {
        if account_index == 0 {
            eyre::bail!("account index cannot be zero");
        }
        let leaf_index = (account_index - 1) as usize;
        let tree = self.tree.read().await;
        match tree.proof(leaf_index) {
            Some(proof) => {
                let resp = ProofResponse::new(
                    account_index,
                    leaf_index as u64,
                    tree.root(),
                    proof_to_vec(&proof),
                );
                Ok(resp)
            }
            None => Err(eyre::eyre!("leaf index out of range")),
        }
    }

    pub async fn account_idx(&mut self) -> u64 {
        self.account_idx
            .recv()
            .await
            .expect("account will be added")
    }
}

async fn update_tree_with_event(
    tree: &RwLock<MerkleTree<PoseidonHasher>>,
    accounts: &RwLock<HashSet<u64>>,
    ev: &DecodedAccountCreated,
) -> eyre::Result<()> {
    let idx = hex_to_u64(&ev.account_index_hex)?;
    if idx == 0 {
        eyre::bail!("account index cannot be zero");
    }
    accounts.write().await.insert(idx);
    let leaf_index = (idx - 1) as usize;
    let value = hex_to_u256(&ev.offchain_signer_commitment_hex)?;
    set_leaf_at_index(tree, leaf_index, value).await;
    Ok(())
}

async fn set_leaf_at_index(
    tree: &RwLock<MerkleTree<PoseidonHasher>>,
    leaf_index: usize,
    value: U256,
) {
    let mut tree = tree.write().await;
    if leaf_index >= tree.num_leaves() {
        panic!("leaf index out of range");
    }
    tree.set(leaf_index, value);
}

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> eyre::Result<DecodedAccountCreated> {
    use alloy::primitives::Log as PLog;
    // Convert RPC log to primitives Log and use typed decoder
    let prim = PLog::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| eyre::eyre!("invalid log for decoding"))?;
    let typed = AccountCreated::decode_log(&prim)?; // returns Log<AccountCreated>
    let ev = typed.data;

    let account_index_hex = format!("0x{:x}", ev.accountIndex);
    let recovery_address_bytes = format!("0x{:x}", ev.recoveryAddress);
    let authenticator_addresses_hex = ev
        .authenticatorAddresses
        .into_iter()
        .map(|a| format!("0x{:x}", a))
        .collect();
    let offchain_signer_commitment_hex = format!("0x{:x}", ev.offchainSignerCommitment);

    Ok(DecodedAccountCreated {
        account_index_hex,
        recovery_address_bytes,
        authenticator_addresses_hex,
        offchain_signer_commitment_hex,
    })
}

fn hex_to_u256(hex_str: &str) -> eyre::Result<U256> {
    let s = hex_str.trim();
    Ok(s.parse()?)
}

fn hex_to_u64(hex_str: &str) -> eyre::Result<u64> {
    let s = hex_str.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(u64::from_str_radix(s, 16)?)
}

fn proof_to_vec(proof: &InclusionProof<PoseidonHasher>) -> Vec<U256> {
    proof
        .0
        .iter()
        .map(|b| match b {
            Branch::Left(sib) => *sib,
            Branch::Right(sib) => *sib,
        })
        .collect()
}

pub const ACCOUNT_REGISTRY: &str = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
pub const ACCOUNT_REGISTRY_TREE_DEPTH: usize = 10;

// forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
pub fn deploy_account_registry(rpc_url: &str) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .arg("script")
        .arg("script/AccountRegistry.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script script/CreateAccount.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
pub fn create_account(rpc_url: &str) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .env("ACCOUNT_REGISTRY", ACCOUNT_REGISTRY)
        .arg("script")
        .arg("script/CreateAccount.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Authenticator holds an internal Alloy signer.
#[derive(Clone, Debug)]
pub struct AuthenticatorSigner {
    onchain_signer: PrivateKeySigner,
    offchain_signer: EdDSAPrivateKey,
}

impl AuthenticatorSigner {
    /// Create a new Authenticator from an input seed string.
    pub fn from_seed_bytes(seed: &[u8]) -> eyre::Result<Self> {
        if seed.len() != 32 {
            return Err(eyre::eyre!("seed must be 32 bytes"));
        }
        let bytes: [u8; 32] = seed.try_into()?;
        let onchain_signer = PrivateKeySigner::from_bytes(&bytes.into())?;
        let offchain_signer = EdDSAPrivateKey::from_bytes(bytes);

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a reference to the internal signer.
    pub fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    pub fn offchain_signer_private_key(&self) -> &EdDSAPrivateKey {
        &self.offchain_signer
    }

    pub fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.public()
    }
}

pub fn fetch_key_material() -> eyre::Result<UserKeyMaterial> {
    let seed = &hex::decode("0101010101010101010101010101010101010101010101010101010101010101")?;
    let auth_signer = AuthenticatorSigner::from_seed_bytes(seed)?;
    // TODO: actually fetch from registry
    let values = std::array::from_fn(|i| {
        if i == 0 {
            let pk = auth_signer.offchain_signer_pubkey();
            pk.pk
        } else {
            ark_babyjubjub::EdwardsAffine::new_unchecked(
                ark_babyjubjub::Fq::ZERO,
                ark_babyjubjub::Fq::ZERO,
            )
        }
    });
    let pk_batch = UserPublicKeyBatch { values };
    let pk_index = 0;
    let sk = auth_signer.offchain_signer_private_key().clone();
    Ok(UserKeyMaterial {
        pk_batch,
        pk_index,
        sk,
    })
}
