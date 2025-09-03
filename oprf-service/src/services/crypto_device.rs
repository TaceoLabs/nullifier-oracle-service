use std::str::FromStr;

use oprf_core::ddlog_equality::{
    DLogEqualityChallenge, DLogEqualityProofShare, DLogEqualitySession,
    PartialDLogEqualityCommitments,
};

use crate::config::{Enviroment, OprfConfig};

type PrivateKey = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

pub(crate) struct CryptoDevice {
    private_key: PrivateKey,
}

impl CryptoDevice {
    pub(crate) fn load_key_by_environment(config: &OprfConfig) -> eyre::Result<Self> {
        let private_key = match config.environment {
            Enviroment::Prod => {
                tracing::info!("starting production environment - loading key from KMS");
                todo!("prod not yet implemented")
            }
            Enviroment::Dev => {
                tracing::warn!("starting dev environment - loading key from file");
                let key_share = std::fs::read_to_string(&config.private_key_share_path)?;
                PrivateKey::from_str(&key_share).unwrap()
            }
        };
        Ok(Self { private_key })
    }

    pub(crate) fn partial_commit(
        &self,
        point_a: Affine,
    ) -> (DLogEqualitySession, PartialDLogEqualityCommitments) {
        tracing::debug!("doing partial commit and sample randomness");
        DLogEqualitySession::partial_commitments(point_a, self.private_key, &mut rand::thread_rng())
    }

    pub(crate) fn challenge(
        &self,
        session: DLogEqualitySession,
        challenge: DLogEqualityChallenge,
    ) -> DLogEqualityProofShare {
        tracing::debug!("finalizing proof share");
        session.challenge(self.private_key, challenge)
    }
}
