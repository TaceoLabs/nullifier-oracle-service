use std::{path::PathBuf, process::Command, str::FromStr, time::Duration};

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
use ark_serialize::CanonicalSerialize as _;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use oprf_world_types::{
    MerkleMembership, MerkleRoot, TREE_DEPTH, UserKeyMaterial, UserPublicKeyBatch,
};
use regex::Regex;
use reqwest::StatusCode;
use world_id_primitives::merkle::AccountInclusionProof;

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

fn leaf_hash(pk: &UserPublicKeyBatch) -> ark_babyjubjub::Fq {
    let mut input = [ark_babyjubjub::Fq::ZERO; 16];
    #[allow(clippy::unwrap_used)]
    {
        input[0] = ark_babyjubjub::Fq::from_str("105702839725298824521994315").unwrap();
    }
    for i in 0..7 {
        input[i * 2 + 1] = pk.values[i].x;
        input[i * 2 + 2] = pk.values[i].y;
    }
    poseidon2::bn254::t16::permutation(&input)[1]
}

pub fn offchain_public_key_compress(pk: &EdDSAPublicKey) -> eyre::Result<U256> {
    let mut compressed_bytes = Vec::new();
    pk.pk.serialize_compressed(&mut compressed_bytes)?;
    Ok(U256::from_le_slice(&compressed_bytes))
}

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
