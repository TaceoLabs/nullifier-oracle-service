use std::collections::HashMap;

use eyre::Context;
use oprf_core::ddlog_equality::{
    DLogEqualityChallenge, DLogEqualityProofShare, DLogEqualitySession,
    PartialDLogEqualityCommitments,
};

use crate::{
    config::OprfConfig,
    services::{
        chain_watcher::KeyEpoch,
        oprf::{KeyIdentifier, RpId},
        secret_manager::SecretManagerService,
    },
};

type PrivateKey = ark_babyjubjub::Fr;
type DLogShare = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

pub(crate) struct CryptoDevice {
    #[expect(dead_code)]
    private_key: secrecy::SecretBox<PrivateKey>,
    shares: HashMap<RpId, HashMap<KeyEpoch, DLogShare>>,
    #[expect(dead_code)]
    secret_manager: SecretManagerService,
}

impl CryptoDevice {
    pub(crate) async fn init(
        config: &OprfConfig,
        secret_manager: SecretManagerService,
        rp_ids: Vec<RpId>,
    ) -> eyre::Result<Self> {
        // load key from secret manager
        let (private_key, shares) = secret_manager
            .load_secrets(config, rp_ids)
            .await
            .context("while loading secrets from AWS")?;
        Ok(Self {
            private_key: secrecy::SecretBox::new(Box::new(private_key)),
            shares,
            secret_manager,
        })
    }

    pub(crate) fn partial_commit(
        &self,
        point_a: Affine,
        key_identifier: &KeyIdentifier,
    ) -> Option<(DLogEqualitySession, PartialDLogEqualityCommitments)> {
        tracing::debug!("doing partial commit and sample randomness");
        let rp = self.shares.get(&key_identifier.rp_id)?;
        let share = rp.get(&key_identifier.key_epoch)?;
        Some(DLogEqualitySession::partial_commitments(
            point_a,
            *share,
            &mut rand::thread_rng(),
        ))
    }

    pub(crate) fn challenge(
        &self,
        session: DLogEqualitySession,
        challenge: DLogEqualityChallenge,
        key_identifier: &KeyIdentifier,
    ) -> Option<DLogEqualityProofShare> {
        tracing::debug!("finalizing proof share");
        let rp = self.shares.get(&key_identifier.rp_id)?;
        let share = rp.get(&key_identifier.key_epoch)?;
        Some(session.challenge(*share, challenge))
    }
}
