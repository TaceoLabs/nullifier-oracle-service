use std::{collections::HashMap, path::PathBuf, process::Command, str::FromStr, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::{Address, Log, TxHash, U256, address},
    providers::{DynProvider, PendingTransaction, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent as _,
    transports::RpcError,
    uint,
};
use ark_ff::{AdditiveGroup as _, BigInt, PrimeField as _};
use ark_serialize::CanonicalSerialize as _;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use futures::StreamExt as _;
use oprf_world_types::{MerkleMembership, TREE_DEPTH, UserKeyMaterial, UserPublicKeyBatch};
use poseidon2::{POSEIDON2_BN254_T2_PARAMS, Poseidon2};
use regex::Regex;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree as MerkleTree};
use semaphore_rs_trees::{Branch, InclusionProof};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

static MASK_ACCOUNT_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        mapping(address => uint256) public authenticatorAddressToPackedAccountIndex;

        function createAccount(
            address recoveryAddress,
            address[] calldata authenticatorAddresses,
            uint256[] calldata authenticatorPubkeys,
            uint256 offchainSignerCommitment
        ) external;
    }
    event AccountCreated(
        uint256 indexed accountIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256[] authenticatorPubkeys,
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
pub struct AccountCreatedEvent {
    pub account_index: U256,
    pub recovery_address: Address,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

/// The response from an inclusion proof request.
/// Copied from [here](https://github.com/worldcoin/world-id-protocol/blob/main/crates/world-id-core/src/types.rs).
#[derive(Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// TODO: Add proper documentation.
    pub account_index: u64,
    /// The index of the leaf in the tree.
    pub leaf_index: u64,
    /// The hash root of the tree.
    pub root: U256,
    /// The entire proof of inclusion for all the nodes in the path.
    pub proof: Vec<U256>,
    /// The authenticator public keys for the account.
    pub authenticator_pubkeys: Vec<U256>,
}

impl InclusionProofResponse {
    /// Instantiates a new inclusion proof response.
    #[must_use]
    pub const fn new(
        account_index: u64,
        leaf_index: u64,
        root: U256,
        proof: Vec<U256>,
        authenticator_pubkeys: Vec<U256>,
    ) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
            authenticator_pubkeys,
        }
    }
}

impl TryFrom<InclusionProofResponse> for MerkleMembership {
    type Error = eyre::Report;

    fn try_from(value: InclusionProofResponse) -> Result<Self, Self::Error> {
        let siblings = value
            .proof
            .into_iter()
            .map(|p| ark_babyjubjub::Fq::new(BigInt(p.into_limbs())))
            .collect::<Vec<_>>();
        if siblings.len() != TREE_DEPTH {
            eyre::bail!("invalid siblings length");
        }
        Ok(MerkleMembership {
            root: value.root.into(),
            mt_index: value.leaf_index,
            siblings: siblings.try_into().expect("correct len"),
        })
    }
}

pub struct AuthTreeIndexer {
    _provider: DynProvider,
    tree: Arc<RwLock<MerkleTree<PoseidonHasher, Canonical>>>,
    accounts: Arc<RwLock<HashMap<u64, AccountCreatedEvent>>>,
}

impl AuthTreeIndexer {
    pub async fn init(contract_address: Address, ws_rpc_url: &str) -> eyre::Result<Self> {
        tracing::info!("creating provider...");
        let tree = Arc::new(RwLock::new(MerkleTree::<_, Canonical>::new(
            TREE_DEPTH,
            U256::ZERO,
        )));
        let accounts = Arc::new(RwLock::new(HashMap::new()));
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
        println!("listening for events...");
        tokio::spawn(async move {
            while let Some(log) = stream.next().await {
                let account_created = decode_account_created(&log).expect("can decode");
                println!(
                    "got account_created account_index: {}",
                    account_created.account_index
                );
                let account_index = account_created.account_index.as_limbs()[0];
                accounts_clone
                    .write()
                    .await
                    .insert(account_index, account_created.clone());
                update_tree_with_event(&tree_clone, &account_created)
                    .await
                    .expect("can update tree");
            }
        });
        Ok(AuthTreeIndexer {
            _provider: provider.erased(),
            tree,
            accounts,
        })
    }

    pub async fn get_proof(&self, account_index: u64) -> eyre::Result<InclusionProofResponse> {
        if account_index == 0 {
            eyre::bail!("account index cannot be zero");
        }
        let account = self
            .accounts
            .read()
            .await
            .get(&account_index)
            .cloned()
            .ok_or_else(|| eyre::eyre!("unknown account index: {account_index}"))?;
        let leaf_index = (account_index - 1) as usize;
        let tree = self.tree.read().await;
        let proof = tree.proof(leaf_index);
        let resp = InclusionProofResponse::new(
            account_index,
            leaf_index as u64,
            tree.root(),
            proof_to_vec(&proof),
            account.authenticator_pubkeys,
        );
        Ok(resp)
    }
}

fn tree_capacity() -> usize {
    1usize << TREE_DEPTH
}

async fn update_tree_with_event(
    tree: &RwLock<MerkleTree<PoseidonHasher, Canonical>>,
    ev: &AccountCreatedEvent,
) -> eyre::Result<()> {
    if ev.account_index == 0 {
        eyre::bail!("account index cannot be zero");
    }
    let leaf_index = ev.account_index.as_limbs()[0] as usize - 1;
    if leaf_index >= tree_capacity() {
        eyre::bail!("leaf index out of range");
    }
    let value = ev.offchain_signer_commitment;
    set_leaf_at_index(tree, leaf_index, value).await;
    Ok(())
}

async fn set_leaf_at_index(
    tree: &RwLock<MerkleTree<PoseidonHasher, Canonical>>,
    leaf_index: usize,
    value: U256,
) {
    let mut tree = tree.write().await;
    if leaf_index >= tree_capacity() {
        panic!("leaf index out of range");
    }
    take_mut::take(&mut *tree, |tree| {
        tree.update_with_mutation(leaf_index, &value)
    });
}

pub fn decode_account_created(lg: &alloy::rpc::types::Log) -> eyre::Result<AccountCreatedEvent> {
    let prim = Log::new(lg.address(), lg.topics().to_vec(), lg.data().data.clone())
        .ok_or_else(|| eyre::eyre!("invalid log for decoding"))?;
    let typed = AccountCreated::decode_log(&prim)?;

    Ok(AccountCreatedEvent {
        account_index: typed.data.accountIndex,
        recovery_address: typed.data.recoveryAddress,
        authenticator_addresses: typed.data.authenticatorAddresses,
        authenticator_pubkeys: typed.data.authenticatorPubkeys,
        offchain_signer_commitment: typed.data.offchainSignerCommitment,
    })
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

// forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
pub fn deploy_account_registry(rpc_url: &str) -> Address {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .arg("script")
        .arg("script/test/AccountRegistry.s.sol")
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
    pub const fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    pub const fn offchain_signer_private_key(&self) -> &EdDSAPrivateKey {
        &self.offchain_signer
    }

    pub const fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.public()
    }

    pub fn offchain_pubkey_compressed(&self) -> eyre::Result<U256> {
        let pk = self.offchain_signer_pubkey().pk;
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes)?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }
}

/// An Authenticator is the base layer with which a user interacts with the Protocol.
pub struct Authenticator {
    signer: AuthenticatorSigner,
    packed_account_index: Option<U256>,
    account_registry_contract: Address,
    provider: DynProvider,
}

impl Authenticator {
    pub async fn new(
        seed: &[u8],
        ws_rpc_url: &str,
        account_registry_contract: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        let signer = AuthenticatorSigner::from_seed_bytes(seed)?;
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().wallet(wallet).connect_ws(ws).await?;
        Ok(Self {
            packed_account_index: None,
            signer,
            account_registry_contract,
            provider: provider.erased(),
        })
    }

    /// Returns the k256 public key of the Authenticator signer which is used to verify on-chain operations,
    /// chiefly with the `AccountRegistry` contract.
    #[must_use]
    pub const fn onchain_address(&self) -> Address {
        self.signer.onchain_signer_address()
    }

    /// Returns the `EdDSA` public key of the Authenticator signer which is used to verify off-chain operations. For example,
    /// the Nullifier Oracle uses it to verify requests for nullifiers.
    #[must_use]
    pub fn offchain_pubkey(&self) -> EdDSAPublicKey {
        self.signer.offchain_signer_pubkey()
    }

    /// Returns the packed account index for the holder's World ID.
    ///
    /// The packed account index is a 256 bit integer which includes the user's account index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn packed_account_index(&mut self) -> eyre::Result<U256> {
        if let Some(packed_account_index) = self.packed_account_index {
            return Ok(packed_account_index);
        }

        let contract = AccountRegistry::new(self.account_registry_contract, self.provider.clone());
        let raw_index = contract
            .authenticatorAddressToPackedAccountIndex(self.signer.onchain_signer_address())
            .call()
            .await?;

        self.packed_account_index = Some(raw_index);
        Ok(raw_index)
    }

    /// Returns the account index for the holder's World ID.
    ///
    /// This is the index at the tree where the holder's World ID account is registered.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn account_index(&mut self) -> eyre::Result<U256> {
        let packed_account_index = self.packed_account_index().await?;
        let tree_index = packed_account_index & MASK_ACCOUNT_INDEX;
        Ok(tree_index)
    }

    /// Returns the raw index at the tree where the holder's World ID account is registered.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn tree_index(&mut self) -> eyre::Result<U256> {
        let account_index = self.account_index().await?;
        Ok(account_index - U256::from(1))
    }

    /// Computes the Merkle leaf for a given public key batch.
    ///
    /// # Errors
    /// Will error if the provided public key batch is not valid.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn leaf_hash(&self, pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
        let poseidon2_16: Poseidon2<ark_babyjubjub::Fq, 16, 5> = Poseidon2::default();
        let mut input = [ark_babyjubjub::Fq::ZERO; 16];
        #[allow(clippy::unwrap_used)]
        {
            input[0] = ark_babyjubjub::Fq::from_str("105702839725298824521994315").unwrap();
        }
        for i in 0..7 {
            input[i * 2 + 1] = pk.values[i].x;
            input[i * 2 + 2] = pk.values[i].y;
        }
        poseidon2_16.permutation(&input)[1]
    }

    /// Creates a new World ID account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    pub async fn create_account(&self) -> eyre::Result<UserKeyMaterial> {
        let mut pubkey_batch = UserPublicKeyBatch {
            values: [ark_babyjubjub::EdwardsAffine::default(); 7],
        };
        pubkey_batch.values[0] = self.offchain_pubkey().pk;
        let leaf_hash = self.leaf_hash(&pubkey_batch);

        let contract = AccountRegistry::new(self.account_registry_contract, self.provider.clone());
        let pending_tx = contract
            .createAccount(
                address!("0x000000000000000000000000000000000000ABCD"),
                vec![self.signer.onchain_signer_address()],
                vec![self.signer.offchain_pubkey_compressed()?],
                leaf_hash.into(),
            )
            .send()
            .await?
            .register()
            .await?;
        let (receipt, _tx_hash) = watch_receipt(self.provider.clone(), pending_tx).await?;
        if !receipt.status() {
            eyre::bail!("could not get receipt for init-key gen");
        }
        Ok(UserKeyMaterial {
            pk_batch: pubkey_batch,
            pk_index: 0,
            sk: self.signer.offchain_signer_private_key().clone(),
        })
    }
}

// FIXME duplicated code from alloy_ken_gen_watcher
async fn watch_receipt(
    provider: DynProvider,
    mut pending_tx: PendingTransaction,
) -> Result<(TransactionReceipt, TxHash), alloy::contract::Error> {
    let tx_hash = pending_tx.tx_hash().to_owned();
    // FIXME: this is a hotfix to prevent a race condition where the heartbeat would miss the
    // block the tx was mined in

    let mut interval = tokio::time::interval(provider.client().poll_interval());

    loop {
        let mut confirmed = false;

        tokio::select! {
            _ = interval.tick() => {},
            res = &mut pending_tx => {
                let _ = res?;
                confirmed = true;
            }
        }

        // try to fetch the receipt
        if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
            return Ok((receipt, tx_hash));
        }

        if confirmed {
            return Err(alloy::contract::Error::TransportError(RpcError::NullResp));
            // FIXME duplicated code from alloy_ken_gen_watcher
        }
    }
}
