//! This module includes the alloy types for the `OprfKeyRegistry` contract.
//!
//! It additionally provides `From`/`TryFrom` implementations to translate from the solidity types to rust land.

use alloy::{primitives::Address, providers::DynProvider, sol};
use oprf_types::crypto::{
    EphemeralEncryptionPublicKey, PartyId, SecretGenCiphertext, SecretGenCiphertexts,
    SecretGenCommitment,
};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    OprfKeyRegistry,
    "../contracts/OprfKeyRegistry.json"
);

impl From<EphemeralEncryptionPublicKey> for Types::BabyJubJubElement {
    fn from(value: EphemeralEncryptionPublicKey) -> Self {
        Self::from(value.inner())
    }
}

impl TryFrom<Types::BabyJubJubElement> for EphemeralEncryptionPublicKey {
    type Error = eyre::Report;

    fn try_from(value: Types::BabyJubJubElement) -> Result<Self, Self::Error> {
        let point = ark_babyjubjub::EdwardsAffine::try_from(value)?;
        Ok(Self::new_unchecked(point))
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

impl From<SecretGenCommitment> for Types::Round1Contribution {
    fn from(value: SecretGenCommitment) -> Self {
        Self {
            commShare: value.comm_share.into(),
            commCoeffs: value.comm_coeffs.into(),
            ephPubKey: value.eph_pub_key.inner().into(),
        }
    }
}

impl From<SecretGenCiphertext> for Types::SecretGenCiphertext {
    fn from(value: SecretGenCiphertext) -> Self {
        Self {
            nonce: value.nonce.into(),
            cipher: value.cipher.into(),
            commitment: value.commitment.into(),
        }
    }
}

impl TryFrom<Types::SecretGenCiphertext> for SecretGenCiphertext {
    type Error = eyre::Report;

    fn try_from(value: Types::SecretGenCiphertext) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: value.nonce.try_into()?,
            cipher: value.cipher.try_into()?,
            commitment: value.commitment.try_into()?,
        })
    }
}

impl From<SecretGenCiphertexts> for Types::Round2Contribution {
    fn from(value: SecretGenCiphertexts) -> Self {
        Self {
            compressedProof: groth16_sol::prepare_compressed_proof(&value.proof.into()),
            ciphers: value.ciphers.into_iter().map(Into::into).collect(),
        }
    }
}

/// Loads the party ID for this node from the OprfKeyRegistry contract.
pub async fn load_party_id(
    contract_address: Address,
    provider: DynProvider,
) -> eyre::Result<PartyId> {
    let contract = OprfKeyRegistry::new(contract_address, provider);
    let party_id = contract.checkIsParticipantAndReturnPartyId().call().await?;
    Ok(PartyId(u16::try_from(party_id)?))
}
