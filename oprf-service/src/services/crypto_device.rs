use oprf_core::ark_serde_compat;
use std::collections::HashMap;
use tracing::instrument;

use eyre::Context;
use oprf_core::ddlog_equality::{
    DLogEqualityChallenge, DLogEqualityProofShare, DLogEqualitySession,
    PartialDLogEqualityCommitments,
};
use oprf_types::{KeyEpoch, RpId, api::v1::KeyIdentifier};
use serde::{Deserialize, Serialize};

use crate::{config::OprfConfig, services::secret_manager::SecretManagerService};

/// The private key of the OPRF-service.
///
/// Used to compute Diffie-Hellman with the Smart Contract. We don't implement Debug/Display on this type to not accidentally leak the key.
#[expect(dead_code)]
pub(crate) struct PrivateKey(ark_babyjubjub::Fr);

/// A share of one of the DLog secrets.
/// We don't implement Debug/Display on this type to not accidentally leak the share.
#[derive(Clone, Serialize, Deserialize)]
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

impl From<ark_babyjubjub::Fr> for PrivateKey {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<ark_babyjubjub::Fr> for DLogShare {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

/// Holds all the cryptographic material of the OPRF-service.
///
/// Does not implement Clone/Debug/Display to keep the material inside the CryptoDevice.
pub(crate) struct CryptoDevice {
    #[expect(dead_code)]
    private_key: PrivateKey,
    shares: HashMap<RpId, HashMap<KeyEpoch, DLogShare>>,
    #[expect(dead_code)]
    secret_manager: SecretManagerService,
}

impl CryptoDevice {
    /// Initializes the [`CryptoDevice`].
    ///
    /// Uses the provided [`SecretManagerService`] to fetch the key-material, by calling [`SecretManagerService::load_secrets`].
    ///
    /// Returns an error if loading the secrets is not possible.
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        config: &OprfConfig,
        secret_manager: SecretManagerService,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<Self> {
        tracing::info!("invoking secret manager to load secrets..");
        // load key from secret manager
        let (private_key, shares) = secret_manager
            .load_secrets(config, rp_ids)
            .await
            .context("while loading secrets from AWS")?;
        Ok(Self {
            private_key,
            shares,
            secret_manager,
        })
    }

    /// Computes C=B*x_share and commitments to a random value k_share, which will be the share of the randomness used in the DlogEqualityProof.
    ///
    /// The provided [`KeyIdentifier`] identifies the RP and the epoch of the key. Iff the RP is not known or the key epoch is not registered returns `None`.
    pub(crate) fn partial_commit(
        &self,
        point_b: Affine,
        key_identifier: &KeyIdentifier,
    ) -> Option<(DLogEqualitySession, PartialDLogEqualityCommitments)> {
        tracing::debug!("doing partial commit and sample randomness");
        let rp = self.shares.get(&key_identifier.rp_id)?;
        let share = rp.get(&key_identifier.key_epoch)?;
        Some(DLogEqualitySession::partial_commitments(
            point_b,
            share.0,
            &mut rand::thread_rng(),
        ))
    }

    /// Finalizes a proof share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    ///
    /// The provided [`KeyIdentifier`] identifies the RP and the epoch of the key. Iff the RP is not known or the key epoch is not registered returns `None`.
    pub(crate) fn challenge(
        &self,
        session: DLogEqualitySession,
        challenge: DLogEqualityChallenge,
        key_identifier: &KeyIdentifier,
    ) -> Option<DLogEqualityProofShare> {
        tracing::debug!("finalizing proof share");
        let rp = self.shares.get(&key_identifier.rp_id)?;
        let share = rp.get(&key_identifier.key_epoch)?;
        Some(session.challenge(share.0, challenge))
    }
}
