use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use ark_ec::CurveGroup;
use oprf_types::{
    RpId,
    chain::ChainEvent,
    crypto::{
        PartyId, PeerPublicKeyList, RpNullifierKey, RpSecretGenCiphertexts, RpSecretGenCommitment,
    },
};
use parking_lot::Mutex;
use tracing::instrument;

use crate::{config::SmartContractMockConfig, services::rp_registry::RpRegistry};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpNullifierGenServiceError {
    #[error("No KeyGen for {0} running")]
    UnknownRp(RpId),
    #[error("We are in Round1")]
    InRound1,
    #[error("We are in Round2")]
    InRound2,
    #[error("Already submitted")]
    AlreadySubmitted,
}

#[derive(Clone)]
pub(crate) struct RpNullifierGenService {
    config: Arc<SmartContractMockConfig>,
    running_key_gens: Arc<Mutex<HashMap<RpId, RpNullifierGenState>>>,
    rp_registry: RpRegistry,
}

struct RpNullifierGenState {
    round1: BTreeMap<PartyId, RpSecretGenCommitment>,
    round2: BTreeMap<PartyId, RpSecretGenCiphertexts>,
    done: HashSet<PartyId>,
    rp_signing_key: k256::SecretKey,
}

impl RpNullifierGenService {
    pub(crate) fn init(config: Arc<SmartContractMockConfig>, rp_registry: RpRegistry) -> Self {
        let init_size = config.init_rp_registry;
        tracing::info!("Spawning {init_size} KeyGen requests");
        let registry = Self {
            config,
            rp_registry,
            running_key_gens: Arc::new(Mutex::new(HashMap::new())),
        };
        for _ in 0..init_size {
            registry.register();
        }
        registry
    }

    pub(crate) fn start_add_rp_task(&self, interval: Duration) {
        let mut interval = tokio::time::interval(interval);
        let registry = self.clone();
        tokio::task::spawn(async move {
            loop {
                interval.tick().await;
                tracing::trace!("adding new rp..");
                registry.register();
            }
        });
    }

    pub(crate) fn register(&self) -> RpId {
        let state = RpNullifierGenState::new();
        let rp_id = RpId::new(rand::random());
        let mut running_key_gens = self.running_key_gens.lock();
        running_key_gens.insert(rp_id, state);
        rp_id
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn read_events(&self, oprf: PartyId) -> eyre::Result<Vec<ChainEvent>> {
        let running_key_gens = self.running_key_gens.lock();
        let mut events = Vec::new();
        for (rp_id, state) in running_key_gens.iter() {
            if state.done.contains(&oprf) {
                continue;
            }
            if !state.round1.contains_key(&oprf) {
                tracing::debug!("round1 for {rp_id}");
                // we need to contribute for round1
                events.push(ChainEvent::round1_event(*rp_id, self.config.oprf_degree));
                continue;
            }
            if !state.round2.contains_key(&oprf) {
                // we already contributed - check if everyone else is ready as well
                if state.round1.len() == self.config.oprf_services {
                    tracing::debug!("round2 for {rp_id}");
                    // we can go!
                    let pk_list =
                        PeerPublicKeyList::new(state.round1.values().map(|c| c.sender).collect());
                    events.push(ChainEvent::round2_event(*rp_id, pk_list));
                    continue;
                } else {
                    tracing::debug!("others are not ready yet..");
                    continue;
                }
            }

            // we are not done, but contributed for round2, lets check if we have all ciphertexts so that we can compute our secret
            let my_ciphers = state
                .round2
                .values()
                .filter_map(|ciphers| ciphers.get_cipher_text(oprf))
                .collect::<Vec<_>>();
            if my_ciphers.len() == self.config.oprf_services {
                // all ciphers are done for me
                events.push(ChainEvent::finalize_event(
                    *rp_id,
                    state.rp_signing_key.public_key(),
                    my_ciphers,
                ));
            } else {
                tracing::debug!(
                    "still waiting for round2 contributions, have {}",
                    my_ciphers.len()
                );
            }
        }
        tracing::debug!("found {} events", events.len());
        Ok(events)
    }

    pub(crate) fn add_round1_contribution(
        &self,
        rp_id: RpId,
        sender: PartyId,
        contribution: RpSecretGenCommitment,
    ) -> Result<(), RpNullifierGenServiceError> {
        let mut running_key_gens = self.running_key_gens.lock();
        let key_gen_state = running_key_gens
            .get_mut(&rp_id)
            .ok_or(RpNullifierGenServiceError::UnknownRp(rp_id))?;

        if !key_gen_state.round2.is_empty() {
            return Err(RpNullifierGenServiceError::InRound2);
        }
        if key_gen_state.round1.contains_key(&sender) {
            return Err(RpNullifierGenServiceError::AlreadySubmitted);
        }
        key_gen_state.round1.insert(sender, contribution);
        tracing::debug!("now has {} contributions", key_gen_state.round1.len());
        Ok(())
    }

    pub(crate) fn add_round2_contribution(
        &self,
        rp_id: RpId,
        sender: PartyId,
        contribution: RpSecretGenCiphertexts,
    ) -> Result<(), RpNullifierGenServiceError> {
        let public_key = {
            let mut running_key_gens = self.running_key_gens.lock();
            let key_gen_state = running_key_gens
                .get_mut(&rp_id)
                .ok_or(RpNullifierGenServiceError::UnknownRp(rp_id))?;
            if key_gen_state.round1.len() != self.config.oprf_services {
                return Err(RpNullifierGenServiceError::InRound1);
            }
            if key_gen_state.round2.contains_key(&sender) {
                return Err(RpNullifierGenServiceError::AlreadySubmitted);
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
        self.rp_registry
            .add_public_key(rp_id, RpNullifierKey::from(public_key));
        Ok(())
    }

    pub(crate) fn oprf_finalize(
        &self,
        rp_id: RpId,
        sender: PartyId,
    ) -> Result<(), RpNullifierGenServiceError> {
        tracing::debug!("finalize for {rp_id} from {sender}");
        let mut running_key_gens = self.running_key_gens.lock();
        let should_remove = {
            let key_gen_state = running_key_gens
                .get_mut(&rp_id)
                .ok_or(RpNullifierGenServiceError::UnknownRp(rp_id))?;
            // check if we are in correct round
            if key_gen_state.round1.len() != self.config.oprf_services {
                return Err(RpNullifierGenServiceError::InRound1);
            } else if key_gen_state.round2.len() != self.config.oprf_services {
                // all good
                return Err(RpNullifierGenServiceError::InRound2);
            } else {
                key_gen_state.done.insert(sender);
                // as soon as all are done we can remove the key gen
                Ok(key_gen_state.done.len() == self.config.oprf_services)
            }
        }?;
        if should_remove {
            tracing::info!("Can remove key gen for {rp_id}!");
        }

        Ok(())
    }
}

impl RpNullifierGenState {
    pub(crate) fn new() -> Self {
        Self {
            round1: BTreeMap::new(),
            round2: BTreeMap::new(),
            done: HashSet::new(),
            rp_signing_key: k256::SecretKey::random(&mut rand::thread_rng()),
        }
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
