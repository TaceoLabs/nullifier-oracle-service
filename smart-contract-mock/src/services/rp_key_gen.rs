use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use ark_ec::CurveGroup;
use oprf_types::{
    RpId,
    crypto::{RpSecretGenCiphertext, RpSecretGenCiphertexts, RpSecretGenCommitment},
};

use crate::{config::SmartContractMockConfig, services::rp_registry::RpRegistry};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpKeyGenServiceError {
    #[error("No KeyGen for {0} running")]
    UnknownRp(RpId),
    #[error("We are still in Round1")]
    InRound1,
    #[error("We are already in Round2")]
    InRound2,
    #[error("Already submitted")]
    AlreadySubmitted,
}

#[derive(Clone)]
pub(crate) struct RpKeyGenService {
    config: Arc<SmartContractMockConfig>,
    running_key_gens: Arc<Mutex<HashMap<RpId, RpKeyGenState>>>,
    rp_registry: RpRegistry,
}

#[derive(Default)]
struct RpKeyGenState {
    round1: HashMap<ark_babyjubjub::EdwardsAffine, RpSecretGenCommitment>,
    round2: HashMap<ark_babyjubjub::EdwardsAffine, RpSecretGenCiphertexts>,
}

impl RpKeyGenService {
    pub(crate) fn init(config: Arc<SmartContractMockConfig>, rp_registry: RpRegistry) -> Self {
        Self {
            config,
            rp_registry,
            running_key_gens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn register(&self) -> RpId {
        let state = RpKeyGenState::new();
        let rp_id = RpId::new(rand::random());
        let mut running_key_gens = self.running_key_gens.lock().expect("not poisoned");
        running_key_gens.insert(rp_id, state);
        rp_id
    }

    pub(crate) fn add_round1_contribution(
        &self,
        rp_id: RpId,
        sender: ark_babyjubjub::EdwardsAffine,
        contribution: RpSecretGenCommitment,
    ) -> Result<(), RpKeyGenServiceError> {
        let mut running_key_gens = self.running_key_gens.lock().expect("not poisoned");
        let key_gen_state = running_key_gens.get_mut(&rp_id).unwrap();
        if !key_gen_state.round2.is_empty() {
            return Err(RpKeyGenServiceError::InRound2);
        }
        if key_gen_state.round1.contains_key(&sender) {
            return Err(RpKeyGenServiceError::AlreadySubmitted);
        }
        key_gen_state.round1.insert(sender, contribution);
        Ok(())
    }

    pub(crate) fn read_round1_contributions(
        &self,
        rp_id: RpId,
    ) -> Result<Vec<RpSecretGenCommitment>, RpKeyGenServiceError> {
        let running_key_gens = self.running_key_gens.lock().expect("not poisoned");
        let key_gen_state = running_key_gens
            .get(&rp_id)
            .ok_or(RpKeyGenServiceError::UnknownRp(rp_id))?;
        Ok(key_gen_state.round1.values().cloned().collect())
    }

    pub(crate) fn add_round2_contribution(
        &self,
        rp_id: RpId,
        sender: ark_babyjubjub::EdwardsAffine,
        contribution: RpSecretGenCiphertexts,
    ) -> Result<(), RpKeyGenServiceError> {
        let public_key = {
            let mut running_key_gens = self.running_key_gens.lock().expect("not poisoned");
            let key_gen_state = running_key_gens
                .get_mut(&rp_id)
                .ok_or(RpKeyGenServiceError::UnknownRp(rp_id))?;
            if key_gen_state.round1.len() != self.config.oprf_services {
                return Err(RpKeyGenServiceError::InRound1);
            }
            if key_gen_state.round2.contains_key(&sender) {
                return Err(RpKeyGenServiceError::AlreadySubmitted);
            }
            key_gen_state.round2.insert(sender, contribution);
            // check if we are done
            if key_gen_state.round2.len() == self.config.oprf_services {
                // finish
                key_gen_state.finish()
            } else {
                return Ok(());
            }
        };
        self.rp_registry.add_public_key(rp_id, public_key);
        Ok(())
    }

    pub(crate) fn read_round2_contributions(
        &self,
        rp_id: RpId,
        sender: ark_babyjubjub::EdwardsAffine,
    ) -> Result<Vec<RpSecretGenCiphertext>, RpKeyGenServiceError> {
        let mut running_key_gens = self.running_key_gens.lock().expect("not poisoned");
        let key_gen_state = running_key_gens
            .get_mut(&rp_id)
            .ok_or(RpKeyGenServiceError::UnknownRp(rp_id))?;

        Ok(key_gen_state
            .round2
            .values()
            .map(|c| c.get_cipher_text(sender))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default())
    }
}

impl RpKeyGenState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn finish(&self) -> ark_babyjubjub::EdwardsAffine {
        // According to the protocol the smart contract should check whether the commitments provided by the OPRF-Services are distinct. We skip this check as the chance of it happening accidentally is negligible and they need to provide a proof anyways.
        //
        // Compute the Public Key
        self.round1.values().fold(
            ark_babyjubjub::EdwardsAffine::zero(),
            |acc, contribution| (acc + contribution.comm_share).into_affine(),
        )
    }
}
