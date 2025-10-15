use std::{
    collections::HashSet, path::PathBuf, process::Command, str::FromStr, sync::Arc, time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent as _,
};
use ark_ff::{AdditiveGroup as _, BigInt, PrimeField as _};
use futures::StreamExt as _;
use oprf_client::{EdDSAPrivateKey, EdDSAPublicKey, MAX_DEPTH, MerkleMembership, UserKeyMaterial};
use oprf_types::crypto::UserPublicKeyBatch;
use poseidon2::{POSEIDON2_BN254_T2_PARAMS, Poseidon2};
use regex::Regex;
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

/// The response from an inclusion proof request.
/// Copied from [here](https://github.com/worldcoin/world-id-protocol/blob/main/crates/world-id-core/src/types.rs).
#[derive(Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// The account index
    pub account_index: u64,
    /// The index of the leaf in the tree.
    pub leaf_index: u64,
    /// The hash root of the tree.
    pub root: U256,
    /// The entire proof of inclusion for all the nodes in the path.
    pub proof: Vec<U256>,
}

impl InclusionProofResponse {
    /// Instantiates a new inclusion proof response.
    pub const fn new(account_index: u64, leaf_index: u64, root: U256, proof: Vec<U256>) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
        }
    }
}

impl From<InclusionProofResponse> for MerkleMembership {
    fn from(value: InclusionProofResponse) -> Self {
        let depth = value.proof.len() as u64;
        let mut siblings = value
            .proof
            .into_iter()
            .map(|p| ark_babyjubjub::Fq::new(BigInt(p.into_limbs())))
            .collect::<Vec<_>>();
        // pad siblings to max depth
        for _ in 0..MAX_DEPTH as u64 - depth {
            siblings.push(ark_babyjubjub::Fq::default());
        }
        MerkleMembership {
            root: value.root.into(),
            depth, // send actual depth of contract merkle tree
            mt_index: value.leaf_index,
            siblings: siblings.try_into().expect("padded ot correct len"),
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
        contract_address: Address,
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

        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
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

    pub async fn get_proof(&self, account_index: u64) -> eyre::Result<InclusionProofResponse> {
        if account_index == 0 {
            eyre::bail!("account index cannot be zero");
        }
        let leaf_index = (account_index - 1) as usize;
        let tree = self.tree.read().await;
        match tree.proof(leaf_index) {
            Some(proof) => {
                let resp = InclusionProofResponse::new(
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

    pub async fn account_idx(&mut self) -> eyre::Result<u64> {
        Ok(
            tokio::time::timeout(Duration::from_secs(30), self.account_idx.recv())
                .await?
                .expect("account will be added"),
        )
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

pub const ACCOUNT_REGISTRY_TREE_DEPTH: usize = 10;

// TREE_DEPTH=10 forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
pub fn deploy_account_registry(rpc_url: &str, tree_depth: usize) -> Address {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .env("TREE_DEPTH", tree_depth.to_string())
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"AccountRegistry deployed to:\s*(0x[0-9a-fA-F]{40})").unwrap();
    let addr = re
        .captures(&stdout)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect("failed to parse deployed address from script output");
    Address::from_str(&addr).expect("valid addr")
}

// ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script script/CreateAccount.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
pub fn create_account(rpc_url: &str, account_registry_contract: &str) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .env("ACCOUNT_REGISTRY", account_registry_contract)
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
#[derive(Clone)]
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
