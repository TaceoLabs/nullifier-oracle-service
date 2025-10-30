use std::{
    ops::{Deref, DerefMut},
    path::PathBuf,
    process::Command,
    str::FromStr,
    time::Duration,
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, TxHash, U256, address},
    providers::{DynProvider, PendingTransaction, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
    transports::RpcError,
    uint,
};
use ark_ff::AdditiveGroup as _;
use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};
use oprf_client::{EdDSAPrivateKey, EdDSAPublicKey, MerkleMembership, UserKeyMaterial};
use oprf_types::{MerkleRoot, TREE_DEPTH, crypto::UserPublicKeyBatch};
use poseidon2::Poseidon2;
use regex::Regex;
use reqwest::StatusCode;
use serde::{Deserialize, Deserializer, de::Error};

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

/// Artifact required to compute the Merkle inclusion proof.
///
/// This is generally used to prove inclusion into the set of World ID Accounts (`AccountRegistry`);
/// each authenticator public key is tied to a leaf in a Merkle tree, where each leaf represents
/// a unique World ID Account.
///
/// To prove validity, the user shows membership in the tree with a sibling path up to the root.
#[derive(Debug, Clone, Deserialize)]
pub struct MerkleInclusionProof<const TREE_DEPTH: usize> {
    /// The root hash of the Merkle tree.
    pub root: FieldElement,
    /// The logical index of the user's leaf in the Merkle tree.
    pub leaf_index: u64,
    /// The user's account ID which is represented by the leaf position in the Merkle tree.
    ///
    /// This is the `leaf_index` + 1 (because the `account_id` is initialized to `1`).
    pub account_id: u64,
    /// The sibling path up to the Merkle root.
    pub siblings: Vec<FieldElement>,
}

/// Response containing a Merkle inclusion proof along with the authenticator public keys
/// for a World ID Account.
///
/// This is typically returned by the indexer when requesting proof of account membership.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountInclusionProof<const TREE_DEPTH: usize> {
    /// The Merkle inclusion proof.
    #[serde(flatten)]
    pub proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The compressed authenticator public keys for the account (as `U256` values).
    ///
    /// Each public key is serialized in compressed form for efficient storage and transmission.
    pub authenticator_pubkeys: Vec<U256>,
}

/// Represents a field element of the base field (`Fq`) in the World ID Protocol.
///
/// The World ID Protocol uses the `BabyJubJub` curve throughout. Note the
/// base field of `BabyJubJub` is the scalar field of the BN254 curve.
///
/// This wrapper ensures consistent serialization and deserialization of field elements, where
/// string-based serialization is done with hex encoding and binary serialization is done with byte vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FieldElement(ark_babyjubjub::Fq);

impl Deref for FieldElement {
    type Target = ark_babyjubjub::Fq;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FieldElement {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for FieldElement {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let u256 = U256::from_str_radix(s, 16).map_err(|_| {
            TypeError::Deserialization("not a valid hex-encoded number".to_string())
        })?;
        u256.try_into()
    }
}

impl From<ark_babyjubjub::Fq> for FieldElement {
    fn from(value: ark_babyjubjub::Fq) -> Self {
        Self(value)
    }
}

impl TryFrom<U256> for FieldElement {
    type Error = TypeError;
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| TypeError::NotInField)?))
    }
}

impl From<FieldElement> for U256 {
    fn from(value: FieldElement) -> Self {
        <Self as From<ark_babyjubjub::Fq>>::from(value.0)
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(D::Error::custom)
    }
}

/// Generic errors that may occur with basic serialization and deserialization.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// Error that occurs when serializing a value. Generally not expected.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Error that occurs when deserializing a value. This can happen often when not providing valid inputs.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// Number is equal or larger than the target field modulus.
    #[error("Provided value is not in the field")]
    NotInField,
    /// Index is out of bounds.
    #[error("Provided index is out of bounds")]
    OutOfBounds,
}

/// Computes the Merkle leaf for a given public key batch.
///
/// # Errors
/// Will error if the provided public key batch is not valid.
#[allow(clippy::missing_panics_doc)]
#[must_use]
fn leaf_hash(pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
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

pub fn offchain_public_key_compress(pk: &EdDSAPublicKey) -> eyre::Result<U256> {
    let mut compressed_bytes = Vec::new();
    pk.pk.serialize_compressed(&mut compressed_bytes)?;
    Ok(U256::from_le_slice(&compressed_bytes))
}

/// Creates a new World ID account.
///
/// # Errors
/// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
pub async fn create_account(
    offchain_signer_private_key: EdDSAPrivateKey,
    onchain_signer: &PrivateKeySigner,
    ws_rpc_url: &str,
    contract_address: Address,
    wallet: EthereumWallet,
) -> eyre::Result<UserKeyMaterial> {
    let ws = WsConnect::new(ws_rpc_url);
    let provider = ProviderBuilder::new().wallet(wallet).connect_ws(ws).await?;
    let contract = AccountRegistry::new(contract_address, provider.clone());
    let mut pubkey_batch = UserPublicKeyBatch {
        values: [ark_babyjubjub::EdwardsAffine::default(); 7],
    };
    pubkey_batch.values[0] = offchain_signer_private_key.public().pk;
    let leaf_hash = leaf_hash(&pubkey_batch);
    let pending_tx = contract
        .createAccount(
            address!("0x000000000000000000000000000000000000ABCD"),
            vec![onchain_signer.address()],
            vec![offchain_public_key_compress(
                &offchain_signer_private_key.public(),
            )?],
            leaf_hash.into(),
        )
        .send()
        .await?
        .register()
        .await?;
    let (receipt, _tx_hash) = watch_receipt(provider.erased(), pending_tx).await?;
    if !receipt.status() {
        eyre::bail!("could not get receipt for init-key gen");
    }
    Ok(UserKeyMaterial {
        pk_batch: pubkey_batch,
        pk_index: 0,
        sk: offchain_signer_private_key.clone(),
    })
}

pub async fn fetch_inclusion_proof(
    onchain_signer: &PrivateKeySigner,
    ws_rpc_url: &str,
    contract_address: Address,
    wallet: EthereumWallet,
    indexer_url: &str,
    timeout: Duration,
) -> eyre::Result<MerkleMembership> {
    let ws = WsConnect::new(ws_rpc_url);
    let provider = ProviderBuilder::new().wallet(wallet).connect_ws(ws).await?;
    let contract = AccountRegistry::new(contract_address, provider.clone());
    // let account_index = authenticator.account_index().await?;
    let account_index = contract
        .authenticatorAddressToPackedAccountIndex(onchain_signer.address())
        .call()
        .await?;
    if account_index == U256::ZERO {
        eyre::bail!("account does not exist")
    }
    const MASK_ACCOUNT_INDEX: U256 =
        uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);
    let account_index = account_index & MASK_ACCOUNT_INDEX;
    tokio::time::timeout(timeout, async {
        loop {
            let res = reqwest::get(format!("{indexer_url}/proof/{account_index}")).await?;
            if res.status() == StatusCode::OK {
                return eyre::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await??;
    let url = format!("{indexer_url}/proof/{account_index}");
    let response = reqwest::get(url).await?;
    let response = response.json::<AccountInclusionProof<TREE_DEPTH>>().await?;

    let mut pubkey_batch = [ark_babyjubjub::EdwardsAffine::default(); 7];

    for (i, pk) in response.authenticator_pubkeys.into_iter().enumerate() {
        pubkey_batch[i] = ark_babyjubjub::EdwardsAffine::deserialize_compressed(pk.as_le_slice())?;
    }
    let merkle_membership = MerkleMembership {
        root: MerkleRoot::from(*response.proof.root),
        mt_index: response.proof.leaf_index,
        siblings: response
            .proof
            .siblings
            .into_iter()
            .map(|s| *s)
            .collect::<Vec<_>>()
            .try_into()
            .expect("lex is 30"),
    };
    Ok(merkle_membership)
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
