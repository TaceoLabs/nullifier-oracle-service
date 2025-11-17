//! This module includes the alloy types for the RpRegistry.
//!
//! It additionally provides `From`/`TryFrom` implementations to translate from the solidity types to rust land.

use alloy::sol;
use ark_bn254::Bn254;
use circom_types::groth16::Proof;
use k256::EncodedPoint;
use oprf_types::crypto::{
    PeerPublicKey, RpSecretGenCiphertext, RpSecretGenCiphertexts, RpSecretGenCommitment,
};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    RpRegistry,
    "../contracts/RpRegistry.json"
);

impl From<PeerPublicKey> for Types::BabyJubJubElement {
    fn from(value: PeerPublicKey) -> Self {
        Self::from(value.inner())
    }
}

impl TryFrom<Types::BabyJubJubElement> for PeerPublicKey {
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

impl From<RpSecretGenCommitment> for Types::Round1Contribution {
    fn from(value: RpSecretGenCommitment) -> Self {
        Self {
            commShare: value.comm_share.into(),
            commCoeffs: value.comm_coeffs.into(),
            ephPubKey: value.eph_pub_key.inner().into(),
        }
    }
}

impl From<Proof<Bn254>> for Types::Groth16Proof {
    fn from(value: Proof<Bn254>) -> Self {
        Self {
            pA: [value.pi_a.x.into(), value.pi_a.y.into()],
            // This is not a typo - must be c1 and then c0
            pB: [
                [value.pi_b.x.c1.into(), value.pi_b.x.c0.into()],
                [value.pi_b.y.c1.into(), value.pi_b.y.c0.into()],
            ],
            pC: [value.pi_c.x.into(), value.pi_c.y.into()],
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
