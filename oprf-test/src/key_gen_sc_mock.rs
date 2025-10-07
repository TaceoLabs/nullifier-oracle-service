use ark_ec::CurveGroup;
use std::{collections::HashMap, path::PathBuf, process::Command, time::Duration};

use k256::ecdsa::signature::Signer as _;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, TxHash, address},
    providers::{DynProvider, PendingTransaction, Provider, ProviderBuilder, WsConnect},
    rpc::types::TransactionReceipt,
    signers::k256::{self},
    sol,
    transports::RpcError,
};
use eyre::Context as _;
use oprf_types::{
    RpId,
    crypto::{RpNullifierKey, RpSecretGenCommitment},
};

pub const DEFAULT_KEY_GEN_CONTRACT_ADDRESS: Address =
    address!("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");

pub fn deploy_key_gen_contract(rpc_url: &str) {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cmd.current_dir(dir.join("../contracts"))
        .arg("script")
        .arg("script/KeyGen.s.sol")
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

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    KeyGenContract,
    "../contracts/KeyGen.json"
);

pub struct KeyGenProxy {
    provider: DynProvider,
    contract_address: Address,
    secret_keys: HashMap<RpId, k256::ecdsa::SigningKey>,
    nullifier_keys: HashMap<RpId, RpNullifierKey>,
}

impl KeyGenProxy {
    pub async fn connect(
        rpc_url: &str,
        contract_address: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        tracing::debug!("connecting to {rpc_url}...");

        let ws = WsConnect::new(rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?;
        Ok(Self {
            provider: provider.erased(),
            contract_address,
            secret_keys: HashMap::new(),
            nullifier_keys: HashMap::new(),
        })
    }

    pub fn sign(&self, rp_id: RpId, msg: &[u8]) -> Option<k256::ecdsa::Signature> {
        let sk = self.secret_keys.get(&rp_id)?;
        Some(sk.sign(msg))
    }

    pub async fn init_key_gen(&mut self) -> eyre::Result<(RpId, RpNullifierKey)> {
        let contract = KeyGenContract::new(self.contract_address, self.provider.clone());
        let rp_id = RpId::new(rand::random());
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk_bytes = bincode::serde::encode_to_vec(sk.public_key(), bincode::config::standard())
            .expect("can serialize");
        let pending_tx = contract
            .initKeyGen(rp_id.into_inner(), pk_bytes.into())
            .gas(10000000) // FIXME this is only for dummy smart contract
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;
        let (receipt, tx_hash) = watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while watching receipt for init key-gen")?;
        if !receipt.status() {
            eyre::bail!("could not get receipt for init-key gen");
        }
        tracing::debug!("init key gen with hash: {tx_hash}");
        tracing::debug!("starting polling...");
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let commitments = tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                interval.tick().await;
                let commitments = contract
                    .getRpNullifierKey(rp_id.into_inner())
                    .call()
                    .await
                    .context("while polling key gen")?;
                if !commitments.is_empty() {
                    return eyre::Ok(commitments);
                }
            }
        })
        .await
        .context("could not finish key-gen in 5 seconds")?
        .context("while polling RP key")?;
        let commitments = commitments
            .into_iter()
            .map(|c| {
                let bytes = Vec::<u8>::from(c.data);
                let (x, _) = bincode::serde::decode_from_slice::<RpSecretGenCommitment, _>(
                    &bytes,
                    bincode::config::standard(),
                )?;
                eyre::Ok(x)
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        let key = RpNullifierKey::from(commitments.into_iter().fold(
            ark_babyjubjub::EdwardsAffine::zero(),
            |acc, contribution| (acc + contribution.comm_share).into_affine(),
        ));
        self.nullifier_keys.insert(rp_id, key);
        self.secret_keys.insert(rp_id, sk.into());

        Ok((rp_id, key))
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
