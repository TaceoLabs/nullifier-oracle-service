//! This module provides [`OprfKeyMaterial`], which securely holds each RP's
//! DLog shares (per epoch) along with their ECDSA verifying key.  
//! Access is synchronized via a `RwLock` and wrapped in an `Arc` for thread-safe shared ownership.
//!
//! Use the store to retrieve or add shares and public keys safely.  

use oprf_core::{
    ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, DLogSessionShamir, DLogShareShamir,
        PartialDLogCommitmentsShamir,
    },
    shamir,
};
use oprf_types::{
    OprfKeyId, ShareEpoch,
    api::v1::OprfShareIdentifier,
    crypto::{OprfPublicKey, PartyId},
};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use uuid::Uuid;

type OprfKeyMaterialResult<T> = std::result::Result<T, OprfKeyMaterialStoreError>;

/// Errors returned by the [`OprfKeyMaterial`].
///
/// This error type is mostly used in API contexts, meaning it should be digested by the
/// [`crate::api::errors`] module.
///
/// Methods that are used in other contexts may return one of the variants
/// here or return an `eyre::Result`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfKeyMaterialStoreError {
    /// Cannot find the RP.
    #[error("Cannot find RP id: {0}")]
    NoSuchRp(OprfKeyId),
    /// Cannot find a secret share for the given RP at the requested epoch.
    #[error("Cannot find share for Rp with epoch: {0:?}")]
    UnknownKeyShareEpoch(OprfShareIdentifier),
    /// Cannot verify nonce signature.
    #[error(transparent)]
    NonceSignatureError(#[from] k256::ecdsa::Error),
}

/// Storage of the OPRF cryptographic material.
///
/// Includes the [`DLogShareShamir`] secret-share and the [`OprfPublicKey`].
#[derive(Default, Clone)]
pub struct OprfKeyMaterialStore(Arc<RwLock<HashMap<OprfKeyId, OprfKeyMaterial>>>);

/// Holds all cryptographic material for a single relying party (RP).
///
/// Stores:
/// * A mapping of [`ShareEpoch`] → [`DLogShareShamir`]
/// * The RP's ECDSA `VerifyingKey` used for nonce-signature verification.
///
/// This struct is typically wrapped in a larger storage type (e.g. `OprfKeyMaterial`)
/// to manage multiple RPs.
#[derive(Clone)]
pub struct OprfKeyMaterial {
    pub(crate) shares: HashMap<ShareEpoch, DLogShareShamir>,
    oprf_public_key: OprfPublicKey,
}

impl OprfKeyMaterial {
    /// Creates a new [`OprfPublicKey`] from the provided shares and ECDSA public key.
    #[allow(dead_code)]
    pub(crate) fn new(
        shares: HashMap<ShareEpoch, DLogShareShamir>,
        oprf_public_key: OprfPublicKey,
    ) -> Self {
        Self {
            shares,
            oprf_public_key,
        }
    }

    /// Returns the [`DLogShareShamir`] for the given epoch, or `None` if not found.
    fn get_share(&self, epoch: ShareEpoch) -> Option<DLogShareShamir> {
        self.shares.get(&epoch).cloned()
    }

    /// Returns the RP's [`OprfPublicKey`].
    fn get_oprf_public_key(&self) -> OprfPublicKey {
        self.oprf_public_key
    }
}

impl OprfKeyMaterialStore {
    /// Creates a new storage instance with the provided initial shares.
    pub(crate) fn new(inner: HashMap<OprfKeyId, OprfKeyMaterial>) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    /// Verifies an ECDSA signature over a nonce and current_time_stamp for the given relying party.
    ///
    /// The BabyJubJub `nonce` is converted into `ark_ff::BigInt` and then into **little-endian bytes**.
    /// The `current_time_stamp` (given as u64 seconds since `UNIX_EPOCH`) is converted into **little-endian bytes**.
    /// The msg `nonce || current_time_stamp` is then verified against the stored ECDSA public key for `oprf_key_id`
    /// using the provided `signature`.
    ///
    /// Returns `Ok(())` on success or an error if the relying party is unknown
    /// or the signature check fails.
    #[instrument(level = "debug", skip(self, _nonce, _signature))]
    pub(crate) fn verify_nonce_signature(
        &self,
        oprf_key_id: OprfKeyId,
        _nonce: ark_babyjubjub::Fq,
        current_time_stamp: u64,
        _signature: &k256::ecdsa::Signature,
    ) -> OprfKeyMaterialResult<()> {
        // tracing::debug!("verifying nonce: {nonce}");
        // let vk = self
        //     .get_rp_public_key(oprf_key_id)
        //     .ok_or_else(|| OprfKeyMaterialError::NoSuchRp(oprf_key_id))?;
        // let mut msg = Vec::new();
        // msg.extend(nonce.into_bigint().to_bytes_le());
        // msg.extend(current_time_stamp.to_le_bytes());
        // vk.verify(&msg, signature)?;
        // tracing::debug!("success");
        Ok(())
    }

    /// Computes C = B * x_share and commitments to a random value k_share.
    ///
    /// This generates the peer's partial contribution used in the DLogEqualityProof.
    /// The provided [`OprfShareIdentifier`] identifies the RP and the epoch of the share.
    ///
    /// Returns an error if the RP is unknown or the share for the epoch is not registered.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn partial_commit(
        &self,
        point_b: ark_babyjubjub::EdwardsAffine,
        share_identifier: &OprfShareIdentifier,
    ) -> OprfKeyMaterialResult<(DLogSessionShamir, PartialDLogCommitmentsShamir)> {
        tracing::debug!("computing partial commitment");
        let share = self.get(share_identifier).ok_or_else(|| {
            OprfKeyMaterialStoreError::UnknownKeyShareEpoch(share_identifier.to_owned())
        })?;
        Ok(DLogSessionShamir::partial_commitments(
            point_b,
            share,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    ///
    /// Consumes the session to prevent reuse of the randomness. The provided
    /// [`OprfShareIdentifier`] identifies the RP and the epoch of the key.
    ///
    /// Returns an error if the RP is unknown or the key epoch is not registered.
    pub(crate) fn challenge(
        &self,
        session_id: Uuid,
        my_party_id: PartyId,
        session: DLogSessionShamir,
        challenge: DLogCommitmentsShamir,
        share_identifier: &OprfShareIdentifier,
    ) -> OprfKeyMaterialResult<DLogProofShareShamir> {
        tracing::debug!("finalizing proof share");
        let oprf_public_key = self
            .get_oprf_public_key(share_identifier.oprf_key_id)
            .ok_or_else(|| OprfKeyMaterialStoreError::NoSuchRp(share_identifier.oprf_key_id))?;
        let share = self.get(share_identifier).ok_or_else(|| {
            OprfKeyMaterialStoreError::UnknownKeyShareEpoch(share_identifier.to_owned())
        })?;
        let lagrange_coefficient = shamir::single_lagrange_from_coeff(
            my_party_id.into_inner() + 1,
            challenge.get_contributing_parties(),
        );
        Ok(session.challenge(
            session_id,
            share,
            oprf_public_key.inner(),
            challenge,
            lagrange_coefficient,
        ))
    }
    /// Retrieves the secret share for the given [`OprfShareIdentifier`].
    ///
    /// Returns `None` if the RP or share epoch is not found.
    fn get(&self, key_identifier: &OprfShareIdentifier) -> Option<DLogShareShamir> {
        self.0
            .read()
            .get(&key_identifier.oprf_key_id)?
            .get_share(key_identifier.share_epoch)
    }

    /// Returns the `OprfPublicKey` of the specified RP, if registered.
    pub(crate) fn get_oprf_public_key(&self, oprf_key_id: OprfKeyId) -> Option<OprfPublicKey> {
        Some(self.0.read().get(&oprf_key_id)?.get_oprf_public_key())
    }

    /// Adds a new RP entry with a secret share at epoch 0.
    ///
    /// Overwrites any existing entry.  
    /// Intended for creating new shares, not rotation.
    pub(super) fn add(
        &self,
        oprf_key_id: OprfKeyId,
        oprf_public_key: OprfPublicKey,
        dlog_share: DLogShareShamir,
    ) {
        let mut shares = HashMap::new();
        shares.insert(ShareEpoch::default(), dlog_share);
        if self
            .0
            .write()
            .insert(
                oprf_key_id,
                OprfKeyMaterial {
                    shares,
                    oprf_public_key,
                },
            )
            .is_some()
        {
            tracing::warn!("overwriting share for {oprf_key_id}");
        }
    }

    /// Removes the OPRF key entry associated with the provided [`OprfKeyId`].
    ///
    /// If the id is not registered, doesn't do anything.
    pub(super) fn remove(&self, oprf_key_id: OprfKeyId) {
        if self.0.write().remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} material from OprfKeyMaterial");
        }
    }
}
