//! Crypto-device for OPRF peers.
//!
//! This module defines the [`CryptoDevice`] and related types used to hold
//! and manage the cryptographic material of an OPRF peer.
//!
//! The device stores private keys and secret shares securely, never exposing
//! them outside the device. It provides functions to compute public keys,
//! evaluate polynomials, generate partial commitments, and decrypt received
//! ciphertexts.
//!
//! All secret material is persisted using the [`SecretManagerService`] and
//! the device ensures type-safe and consistent handling of cryptographic
//! values.

use ark_ec::{AffineRepr, CurveGroup as _};
use tracing::instrument;

use eyre::Context;
use oprf_core::{
    ddlog_equality::{
        DLogEqualityChallenge, DLogEqualityProofShare, DLogEqualitySession,
        PartialDLogEqualityCommitments,
    },
    keys::keygen::KeyGenPoly,
};
use oprf_types::{
    RpId,
    api::v1::NullifierShareIdentifier,
    crypto::{PeerIdentifier, PeerPublicKey, RpSecretGenCiphertext},
};
use serde::{Deserialize, Serialize};

use crate::{
    metrics::METRICS_RP_SECRETS,
    services::{
        crypto_device::dlog_storage::DLogShareStorage, secret_manager::SecretManagerService,
    },
};

mod dlog_storage;

/// The private key of an OPRF peer.
///
/// Used internally to compute Diffie-Hellman and key-generation operations.
/// Not `Debug`/`Display` to avoid accidental leaks.
#[derive(Copy, Clone)]
pub(crate) struct PeerPrivateKey(ark_babyjubjub::Fr);

/// Secret-share of an OPRF nullifier secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
#[derive(Clone, Copy, Serialize, Deserialize)]
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

impl PeerPrivateKey {
    /// Computes the associated [`PeerPublicKey`] by multiplying the private key with the generator.
    pub fn get_public_key(&self) -> PeerPublicKey {
        PeerPublicKey::from((Affine::generator() * self.0).into_affine())
    }

    /// Returns the inner scalar value of the private key.
    pub fn inner(self) -> ark_babyjubjub::Fr {
        self.0
    }
}

/// Holds all cryptographic material for an OPRF peer.
///
/// Never exposes private keys or secret shares. Provides methods to:
/// - compute public keys
/// - generate partial commitments
/// - evaluate polynomials
/// - decrypt key-generation ciphertexts
#[derive(Clone)]
pub(crate) struct CryptoDevice {
    /// Private key. *Do not return outside the device.*
    private_key: PeerPrivateKey,
    /// Secret shares. *Do not return outside the device.*
    shares: DLogShareStorage,
    /// Associated public key.
    public_key: PeerPublicKey,
    /// Peer identifier derived from the public key.
    identifier: PeerIdentifier,
    /// Service to persist secret material.
    secret_manager: SecretManagerService,
}

impl CryptoDevice {
    /// Initializes the [`CryptoDevice`] by loading secret material from
    /// the provided [`SecretManagerService`].
    ///
    /// Returns an error if loading secrets fails.
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        secret_manager: SecretManagerService,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<Self> {
        tracing::info!("invoking secret manager to load secrets..");
        let (private_key, shares) = secret_manager
            .load_secrets(rp_ids)
            .await
            .context("while loading secrets from AWS")?;
        metrics::counter!(METRICS_RP_SECRETS).increment(shares.len() as u64);
        let public_key = private_key.get_public_key();
        Ok(Self {
            identifier: public_key.to_identifier(),
            public_key,
            private_key,
            shares: DLogShareStorage::new(shares),
            secret_manager,
        })
    }

    /// Returns the public key of this peer.
    pub(crate) fn public_key(&self) -> PeerPublicKey {
        self.public_key
    }

    /// Returns the peer identifier derived from the public key.
    pub(crate) fn oprf_identifier(&self) -> PeerIdentifier {
        self.identifier
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the peer's partial contribution used in the DLogEqualityProof.
    /// The provided [`NullifierShareIdentifier`] identifies the RP and the epoch of the share.
    /// Returns `None` if the RP is unknown or the share for the epoch is not registered.
    pub(crate) fn partial_commit(
        &self,
        point_b: Affine,
        share_identifier: &NullifierShareIdentifier,
    ) -> Option<(DLogEqualitySession, PartialDLogEqualityCommitments)> {
        tracing::debug!("computing partial commitment");
        Some(DLogEqualitySession::partial_commitments(
            point_b,
            self.shares.get(share_identifier)?,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness. The provided
    /// [`NullifierShareIdentifier`] identifies the RP and the epoch of the key.
    /// Returns `None` if the RP is unknown or the key epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session: DLogEqualitySession,
        challenge: DLogEqualityChallenge,
        key_identifier: &NullifierShareIdentifier,
    ) -> Option<DLogEqualityProofShare> {
        tracing::debug!("finalizing proof share");
        Some(session.challenge(self.shares.get(key_identifier)?, challenge))
    }

    /// Registers a new nullifier share for the given relying-party.
    ///
    /// Persists the share using the [`SecretManagerService`].
    pub(crate) fn register_nullifier_share(
        &self,
        rp_id: RpId,
        share: DLogShare,
    ) -> eyre::Result<()> {
        self.shares.add(rp_id, share);
        let result = self.secret_manager.store_dlog_share(rp_id, share);
        metrics::counter!(METRICS_RP_SECRETS).increment(1);
        result
    }

    /// Evaluates the provided polynomial for a peer and encrypts the result.
    ///
    /// Performs a Diffie-Hellman with the private key and the peer’s public key.
    /// Returns the commitment to the share and the encrypted share.
    pub(crate) fn gen_share(
        &self,
        id: usize,
        poly: &KeyGenPoly,
        their_pk: PeerPublicKey,
        nonce: ark_babyjubjub::Fq,
    ) -> (Affine, ark_babyjubjub::Fq) {
        poly.gen_share(id, self.private_key.inner(), their_pk.inner(), nonce)
    }

    /// Decrypts a key-generation ciphertext using the private key.
    ///
    /// Returns the share of the peer's polynomial or an error if decryption fails.
    pub(crate) fn decrypt_key_gen_ciphertext(
        &self,
        cipher: RpSecretGenCiphertext,
    ) -> eyre::Result<ark_babyjubjub::Fr> {
        let RpSecretGenCiphertext {
            sender,
            nonce,
            cipher,
        } = cipher;
        KeyGenPoly::decrypt_share(self.private_key.inner(), sender.inner(), cipher, nonce)
            .context("cannot decrypt share")
    }
}
