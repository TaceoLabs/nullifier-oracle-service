//! Rp registry

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    sol,
};
use ark_ec::AffineRepr as _;
use ark_serde_compat::groth16::Groth16Proof;
use eyre::Context as _;
use k256::EncodedPoint;
use oprf_types::{
    RpId,
    crypto::{
        PeerPublicKey, PeerPublicKeyList, RpNullifierKey, RpSecretGenCiphertext,
        RpSecretGenCiphertexts, RpSecretGenCommitment,
    },
};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    KeyGen,
    "../contracts/KeyGen.json"
);

impl From<PeerPublicKey> for Types::BabyJubJubElement {
    fn from(value: PeerPublicKey) -> Self {
        Self::from(value.inner())
    }
}

impl TryFrom<Types::BabyJubJubElement> for ark_babyjubjub::EdwardsAffine {
    type Error = eyre::Report;

    fn try_from(value: Types::BabyJubJubElement) -> Result<Self, Self::Error> {
        let p = Self::new_unchecked(value.x.try_into()?, value.y.try_into()?);
        if !p.is_on_curve() {
            eyre::bail!("point not on curve");
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            eyre::bail!("point not in correct subgroup");
        }
        Ok(p)
    }
}

impl From<ark_babyjubjub::EdwardsAffine> for Types::BabyJubJubElement {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self {
            x: value.x.into(),
            y: value.y.into(),
        }
    }
}

impl From<RpSecretGenCommitment> for Types::Round1Contribution {
    fn from(value: RpSecretGenCommitment) -> Self {
        Self {
            commShare: value.comm_share.into(),
            commCoeffs: value.comm_coeffs.into(),
        }
    }
}

impl From<Groth16Proof> for Types::Groth16Proof {
    fn from(value: Groth16Proof) -> Self {
        // TODO remove unwraps
        Self {
            pA: [value.a.x().unwrap().into(), value.a.y().unwrap().into()],
            // This is not a typo - must be c1 and then c0
            pB: [
                [
                    value.b.x().unwrap().c1.into(),
                    value.b.x().unwrap().c0.into(),
                ],
                [
                    value.b.y().unwrap().c1.into(),
                    value.b.y().unwrap().c0.into(),
                ],
            ],
            pC: [value.c.x().unwrap().into(), value.c.y().unwrap().into()],
        }
    }
}

impl From<RpSecretGenCiphertext> for Types::SecretGenCiphertext {
    fn from(value: RpSecretGenCiphertext) -> Self {
        Self {
            nonce: value.nonce.into(),
            cipher: value.cipher.into(),
            commitment: value.commitment.into(),
        }
    }
}

impl TryFrom<Types::SecretGenCiphertext> for RpSecretGenCiphertext {
    type Error = eyre::Report;

    fn try_from(value: Types::SecretGenCiphertext) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: value.nonce.try_into()?,
            cipher: value.cipher.try_into()?,
            commitment: value.commitment.try_into()?,
        })
    }
}

impl From<RpSecretGenCiphertexts> for Types::Round2Contribution {
    fn from(value: RpSecretGenCiphertexts) -> Self {
        Self {
            proof: value.proof.into(),
            ciphers: value.ciphers.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<Types::EcDsaPubkeyCompressed> for k256::PublicKey {
    type Error = eyre::Report;

    fn try_from(value: Types::EcDsaPubkeyCompressed) -> Result<Self, Self::Error> {
        let mut bytes = vec![u8::try_from(value.yParity)?];
        bytes.extend(value.x);
        Ok(Self::from_sec1_bytes(&bytes)?)
    }
}

impl TryFrom<k256::PublicKey> for Types::EcDsaPubkeyCompressed {
    type Error = eyre::Report;

    fn try_from(value: k256::PublicKey) -> Result<Self, Self::Error> {
        let encoded_point = EncodedPoint::from(value).compress();
        let bytes = encoded_point.as_bytes();
        let x = &bytes[1..];
        let y_parity = bytes[0];
        Ok(Self {
            x: x.try_into()?,
            yParity: y_parity.try_into()?,
        })
    }
}

#[derive(Clone)]
/// Main struct to interact with the `KeyGen` contract
pub struct RpRegistry {
    pub(crate) contract_address: Address,
    pub(crate) provider: DynProvider,
}

impl RpRegistry {
    /// Create a new `RpRegistry`
    pub async fn init(
        rpc_url: &str,
        contract_address: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        // Create the provider.
        let ws = WsConnect::new(rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?;
        tracing::info!("checking KeyGen ready state at address {contract_address}..");
        let contract = KeyGen::new(contract_address, provider.clone());
        if !contract.isContractReady().call().await? {
            eyre::bail!("KeyGen contract not ready");
        }
        tracing::info!("ready!");

        Ok(Self {
            provider: provider.erased(),
            contract_address,
        })
    }

    /// Fetch the OPRF peer public keys from the contract
    pub async fn fetch_peer_public_keys(&self) -> eyre::Result<PeerPublicKeyList> {
        tracing::info!("fetching peer public keys..");
        let contract = KeyGen::new(self.contract_address, self.provider.clone());
        let peer_public_keys = contract
            .getPeerPublicKeys()
            .call()
            .await?
            .into_iter()
            .map(|pk| Ok(PeerPublicKey::new(pk.try_into()?)))
            .collect::<eyre::Result<Vec<_>>>()?;
        tracing::info!("success");
        Ok(PeerPublicKeyList::new(peer_public_keys))
    }

    /// Fetch the `RpNullifierKey` key from the contract
    pub async fn fetch_rp_nullifier_key(
        &self,
        rp_id: RpId,
        wait_time: Duration,
    ) -> eyre::Result<RpNullifierKey> {
        tracing::info!("fetching rp_nullifier_key..");
        let contract = KeyGen::new(self.contract_address, self.provider.clone());
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let rp_nullifier_key = tokio::time::timeout(wait_time, async move {
            loop {
                interval.tick().await;
                let maybe_rp_nullifier_key =
                    contract.getRpNullifierKey(rp_id.into_inner()).call().await;
                if let Ok(rp_nullifier_key) = maybe_rp_nullifier_key {
                    return eyre::Ok(RpNullifierKey::new(rp_nullifier_key.try_into()?));
                }
            }
        })
        .await
        .context("could not finish key-gen in 5 seconds")?
        .context("while polling RP key")?;
        Ok(rp_nullifier_key)
    }
}
