//! Crypto-device for OPRF peers.
//!
//! This module defines the [`CryptoDevice`] and related types used to hold
//! and manage the cryptographic material of an OPRF peer.
//!
//! The device stores private keys and secret shares securely, never exposing
//! them outside the device. It provides functions to compute public keys,
//! evaluate polynomials, generate partial commitments, decrypt received
//! ciphertexts, and verifies signature from the RPs.
//!
//! All secret material is persisted using the [`SecretManagerService`] and
//! the device ensures type-safe and consistent handling of cryptographic
//! values.

use ark_ec::{AffineRepr, CurveGroup as _};
use ark_ff::{BigInteger as _, PrimeField as _};
use k256::ecdsa::signature::Verifier;
use tracing::instrument;

use eyre::Context;
use oprf_core::{
    ddlog_equality::{
        DLogEqualityCommitments, DLogEqualityProofShare, DLogEqualitySession,
        PartialDLogEqualityCommitments,
    },
    keys::keygen::KeyGenPoly,
};
use oprf_types::{
    RpId,
    api::v1::NullifierShareIdentifier,
    crypto::{PeerPublicKey, PeerPublicKeyList, RpNullifierKey, RpSecretGenCiphertext},
};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    metrics::METRICS_RP_SECRETS,
    services::{
        crypto_device::dlog_storage::RpMaterialStore, secret_manager::SecretManagerService,
    },
};

pub(crate) mod dlog_storage;
mod key_gen;

/// The private key of an OPRF peer.
///
/// Used internally to compute Diffie-Hellman and key-generation operations.
/// Not `Debug`/`Display` to avoid accidental leaks.
#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct PeerPrivateKey(ark_babyjubjub::Fr);

/// Secret-share of an OPRF nullifier secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(crate) struct DLogShare(
    #[serde(
        serialize_with = "ark_serde_compat::serialize_babyjubjub_scalar",
        deserialize_with = "ark_serde_compat::deserialize_babyjubjub_scalar"
    )]
    ark_babyjubjub::Fr,
);

// Type alias for ergonomics
type Affine = ark_babyjubjub::EdwardsAffine;

impl From<ark_babyjubjub::Fr> for PeerPrivateKey {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<ark_babyjubjub::Fr> for DLogShare {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShare> for ark_babyjubjub::Fr {
    fn from(value: DLogShare) -> Self {
        value.0
    }
}

impl PeerPrivateKey {
    /// Computes the associated [`PeerPublicKey`] by multiplying the private key with the generator.
    pub fn get_public_key(&self) -> PeerPublicKey {
        PeerPublicKey::from((Affine::generator() * self.0).into_affine())
    }

    /// Returns the inner scalar value of the private key.
    pub fn inner(&self) -> &ark_babyjubjub::Fr {
        &self.0
    }
}

/// Holds all cryptographic material for an OPRF peer.
///
/// Never exposes private keys or secret shares. Provides methods to:
/// - compute public keys
/// - generate partial commitments
/// - evaluate polynomials
/// - decrypt key-generation ciphertexts
/// - verifies the nonce signature of the RP
pub(crate) struct CryptoDevice {
    /// Private key. *Do not return outside the device.*
    private_key: PeerPrivateKey,
    /// Secret shares and associated public keys of RPs. *Do not return outside the device.*
    shares: RpMaterialStore,
    /// All public keys of the OPRF-peers (incl own key).
    public_key_list: PeerPublicKeyList,
    /// Service to persist secret material.
    secret_manager: SecretManagerService,
}

type CryptoDeviceResult<T> = std::result::Result<T, CryptoDeviceError>;

/// The errors the `CryptoDevice` returns. This error types is mostly
/// used in API contexts, meaning it should be digested by the
/// [`crate::api::errors`] module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoDeviceError {
    /// Cannot find the RP.
    #[error("Cannot find RP id: {0}")]
    NoSuchRp(RpId),
    /// Cannot find a secret share for the given RP at the requested epoch.
    #[error("Cannot find share for Rp with epoch: {0:?}")]
    UnknownRpShareEpoch(NullifierShareIdentifier),
    /// Cannot verify nonce signature.
    #[error(transparent)]
    NonceSignatureError(#[from] k256::ecdsa::Error),
}

impl CryptoDevice {
    /// Initializes the [`CryptoDevice`] by loading secret material from
    /// the provided [`SecretManagerService`].
    ///
    /// Returns an error if loading secrets fails.
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        secret_manager: SecretManagerService,
        public_key_list: PeerPublicKeyList,
    ) -> eyre::Result<Self> {
        tracing::info!("invoking secret manager to load secrets..");
        let (private_key, shares) = secret_manager
            .load_secrets()
            .await
            .context("while loading secrets from AWS")?;
        metrics::counter!(METRICS_RP_SECRETS).increment(shares.len() as u64);

        Ok(Self {
            private_key,
            shares: RpMaterialStore::new(shares),
            public_key_list,
            secret_manager,
        })
    }

    /// Verifies an ECDSA signature over a nonce and current_time_stamp for the given relying party.
    ///
    /// The BabyJubJub `nonce` is converted into `ark_ff::BigInt` and then into **little-endian bytes**.
    /// The `current_time_stamp` (given as u64 seconds since `UNIX_EPOCH`) is converted into **little-endian bytes**.
    /// The msg `nonce || current_time_stamp` is then verified against the stored ECDSA public key for `rp_id`
    /// using the provided `signature`.
    ///
    /// Returns `Ok(())` on success or an error if the relying party is unknown
    /// or the signature check fails.
    #[instrument(level = "debug", skip(self, nonce, signature))]
    pub(super) fn verify_nonce_signature(
        &self,
        rp_id: RpId,
        nonce: ark_babyjubjub::Fq,
        current_time_stamp: u64,
        signature: &k256::ecdsa::Signature,
    ) -> CryptoDeviceResult<()> {
        tracing::debug!("verifying nonce: {nonce}");
        let vk = self
            .shares
            .get_rp_public_key(rp_id)
            .ok_or_else(|| CryptoDeviceError::NoSuchRp(rp_id))?;
        let mut msg = Vec::new();
        msg.extend(nonce.into_bigint().to_bytes_le());
        msg.extend(current_time_stamp.to_le_bytes());
        vk.verify(&msg, signature)?;
        tracing::debug!("success");
        Ok(())
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the peer's partial contribution used in the DLogEqualityProof.
    /// The provided [`NullifierShareIdentifier`] identifies the RP and the epoch of the share.
    ///
    /// Returns an error if the RP is unknown or the share for the epoch is not registered.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: Affine,
        share_identifier: &NullifierShareIdentifier,
    ) -> CryptoDeviceResult<(DLogEqualitySession, PartialDLogEqualityCommitments)> {
        tracing::debug!("computing partial commitment");
        let share = self
            .shares
            .get(share_identifier)
            .ok_or_else(|| CryptoDeviceError::UnknownRpShareEpoch(share_identifier.to_owned()))?;
        Ok(DLogEqualitySession::partial_commitments(
            point_b,
            share,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness. The provided
    /// [`NullifierShareIdentifier`] identifies the RP and the epoch of the key.
    ///
    /// Returns an error if the RP is unknown or the key epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session: DLogEqualitySession,
        challenge: DLogEqualityCommitments,
        share_identifier: &NullifierShareIdentifier,
    ) -> CryptoDeviceResult<DLogEqualityProofShare> {
        tracing::debug!("finalizing proof share");
        let rp_nullifier_key = self
            .shares
            .get_rp_nullifier_key(share_identifier.rp_id)
            .ok_or_else(|| CryptoDeviceError::NoSuchRp(share_identifier.rp_id))?;
        let share = self
            .shares
            .get(share_identifier)
            .ok_or_else(|| CryptoDeviceError::UnknownRpShareEpoch(share_identifier.to_owned()))?;
        Ok(session.challenge(share, rp_nullifier_key.inner(), challenge))
    }

    /// Registers a new nullifier share for the given relying-party.
    ///
    /// Persists the share using the [`SecretManagerService`].
    pub(crate) async fn register_nullifier_share(
        &self,
        rp_id: RpId,
        rp_public_key: k256::ecdsa::VerifyingKey,
        rp_nullifier_key: RpNullifierKey,
        share: DLogShare,
    ) -> eyre::Result<()> {
        self.shares
            .add(rp_id, rp_public_key, rp_nullifier_key, share.clone());
        let result = self
            .secret_manager
            .store_dlog_share(rp_id, rp_public_key.into(), rp_nullifier_key, share)
            .await;
        metrics::counter!(METRICS_RP_SECRETS).increment(1);
        result
    }

    /// Decrypts a key-generation ciphertext using the private key.
    ///
    /// Returns the share of the peer's polynomial or an error if decryption fails.
    pub(crate) fn decrypt_key_gen_ciphertexts(
        &self,
        ciphers: Vec<RpSecretGenCiphertext>,
    ) -> eyre::Result<DLogShare> {
        // In some later version, we maybe need some meaningful way
        // to tell which party produced a wrong ciphertext. Currently,
        // we trust the smart-contract to verify the proof, therefore
        // it should never happen that this here fails. If yes, there is
        // a bug.
        //
        // In some future version, we might have an optimistic approach
        // where we don't verify the proof and need to pinpoint the
        // scoundrel.
        let shares = ciphers
            .into_iter()
            .enumerate()
            .map(|(idx, cipher)| {
                let RpSecretGenCiphertext {
                    nonce,
                    cipher,
                    commitment,
                } = cipher;
                let their_pk = self.public_key_list[idx].inner();
                let share =
                    KeyGenPoly::decrypt_share(self.private_key.inner(), their_pk, cipher, nonce)
                        .context("cannot decrypt share ciphertext from peer")?;
                // check commitment
                let is_commitment =
                    (ark_babyjubjub::EdwardsAffine::generator() * share).into_affine();
                // This is actually not possible if Smart Contract verified proof
                if is_commitment == commitment {
                    eyre::Ok(share)
                } else {
                    eyre::bail!("Commitment for {idx} wrong");
                }
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(DLogShare::from(KeyGenPoly::accumulate_shares(&shares)))
    }

    pub(crate) fn peer_public_key(&self) -> PeerPublicKey {
        self.private_key.get_public_key()
    }
}
