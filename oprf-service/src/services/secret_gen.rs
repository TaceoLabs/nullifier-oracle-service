//! Distributed Logarithm (DLog) Secret Generation Service
//!
//! This service handles the distributed secret generation protocol for RPs.
//! It maintains temporary state for the ongoing key generation rounds
//! and interacts with the [`CryptoDevice`] for cryptographic operations.
//!
//! **Important:** This service is **not thread-safe**. It is intended to be used
//! only in contexts where a single dedicated task owns the struct. No internal
//! locking (`Mutex`) or reference counting (`Arc`) is performed, so multiple tasks
//! must not concurrently access it.
//!
//! We refer to [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-nullifier
//! generation protocol.

use std::{collections::HashMap, sync::Arc};

use ark_ec::CurveGroup as _;
use ark_ff::UniformRand;
use oprf_core::keys::keygen::KeyGenPoly;
use oprf_types::{
    RpId,
    chain::{
        SecretGenFinalizeContribution, SecretGenRound1Contribution, SecretGenRound2Contribution,
    },
    crypto::{
        PartyId, PeerPublicKeyList, RpNullifierKey, RpSecretGenCiphertext, RpSecretGenCiphertexts,
        RpSecretGenCommitment,
    },
};
use tracing::instrument;

use crate::services::crypto_device::{CryptoDevice, DLogShare};

// Type for ergonomics
type BaseField = ark_babyjubjub::Fq;

/// Service for managing the distributed secret generation protocol.
///
/// Handles round 1 and round 2 of secret generation, and finalizes
/// by producing the party's share of the secret.
///
/// **Note:** Must only be used in a single-owner context. Do not share across tasks.
pub(crate) struct DLogSecretGenService {
    pub(crate) party_id: PartyId,
    round1: HashMap<RpId, KeyGenPoly>,
    crypto_device: Arc<CryptoDevice>,
}

impl DLogSecretGenService {
    /// Initializes a new DLog secret generation service.
    pub(crate) fn init(party_id: PartyId, crypto_device: Arc<CryptoDevice>) -> Self {
        Self {
            crypto_device,
            party_id,
            round1: HashMap::new(),
        }
    }

    /// Executes round 1 of the secret generation protocol.
    ///
    /// Generates a polynomial of the specified degree and stores it internally.
    /// Returns a [`SecretGenRound1Contribution`] containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `rp_id` - Identifier of the RP for which the secret is being generated.
    /// * `degree` - Degree of the polynomial to generate (threshold).
    #[instrument(level = "info", skip(self))]
    pub(crate) fn round1(&mut self, rp_id: RpId, degree: u16) -> SecretGenRound1Contribution {
        tracing::info!("secret gen round1..");
        let mut rng = rand::thread_rng();
        let poly = KeyGenPoly::keygen(&mut rng, usize::from(degree));
        let contribution = RpSecretGenCommitment {
            sender: self.crypto_device.public_key(),
            comm_share: poly.get_pk_share(),
            comm_coeffs: poly.get_coeff_commitment(),
        };
        let old_value = self.round1.insert(rp_id, poly);
        // TODO handle this more gracefully
        assert!(
            old_value.is_none(),
            "already had this round1 - this is a bug"
        );
        SecretGenRound1Contribution {
            rp_id,
            contribution,
            sender: self.party_id,
        }
    }

    /// Executes round 2 of the secret generation protocol.
    ///
    /// Generates secret shares for all peers based on the polynomial generated in round 1.
    /// Returns a [`SecretGenRound2Contribution`] containing ciphertexts for all parties.
    ///
    /// # Arguments
    /// * `rp_id` - Identifier of the RP for which the secret is being generated.
    /// * `peers` - List of public keys for peers participating in the protocol.
    pub(crate) fn round2(
        &mut self,
        rp_id: RpId,
        peers: PeerPublicKeyList,
    ) -> SecretGenRound2Contribution {
        let mut rng = rand::thread_rng();
        let my_poly = self.round1.remove(&rp_id).expect("todo how to handle this");
        let my_pk = self.crypto_device.public_key();
        let mut ciphers = HashMap::with_capacity(peers.len());
        // Create party secret and public key
        // We create one for us as well
        for (party_id, their_pk) in peers.into_iter().enumerate() {
            let nonce = BaseField::rand(&mut rng);
            let (_, cipher) = self
                .crypto_device
                .gen_share(party_id, &my_poly, their_pk, nonce);
            ciphers.insert(
                PartyId::from(party_id as u16),
                RpSecretGenCiphertext {
                    sender: my_pk,
                    nonce,
                    cipher,
                },
            );
        }
        SecretGenRound2Contribution {
            rp_id,
            sender: self.party_id,
            contribution: RpSecretGenCiphertexts::new(ciphers),
        }
    }

    /// Finalizes secret generation by decrypting received ciphertexts and
    /// computing the final secret share for this party.
    ///
    /// The resulting share is registered in the [`CryptoDevice`] for later use.
    ///
    /// # Arguments
    /// * `rp_id` - Identifier of the RP for which the secret is being finalized.
    /// * `ciphers` - Ciphertexts received from other parties in round 2.
    #[instrument(level = "info", skip(self, rp_public, ciphers))]
    pub(crate) async fn finalize(
        &self,
        rp_id: RpId,
        rp_public: k256::PublicKey,
        commitments: Vec<RpSecretGenCommitment>,
        ciphers: Vec<RpSecretGenCiphertext>,
    ) -> SecretGenFinalizeContribution {
        tracing::info!("calling finalize with {}", ciphers.len());
        let shares = ciphers
            .into_iter()
            .map(|x| self.crypto_device.decrypt_key_gen_ciphertext(x))
            .collect::<eyre::Result<Vec<_>>>()
            .expect("TODO");
        let my_share = DLogShare::from(KeyGenPoly::accumulate_shares(&shares));
        let rp_nullifier_key = RpNullifierKey::from(commitments.into_iter().fold(
            ark_babyjubjub::EdwardsAffine::zero(),
            |acc, contribution| (acc + contribution.comm_share).into_affine(),
        ));
        self.crypto_device
            .register_nullifier_share(
                rp_id,
                k256::ecdsa::VerifyingKey::from(rp_public),
                rp_nullifier_key,
                my_share,
            )
            .await
            .expect("TODO");
        SecretGenFinalizeContribution {
            rp_id,
            sender: self.party_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::{CurveGroup as _, PrimeGroup};
    use oprf_types::ShareEpoch;
    use rand::{CryptoRng, Rng};

    use crate::services::{crypto_device::PeerPrivateKey, secret_manager::test::TestSecretManager};

    use super::*;

    async fn secret_manager_and_dlog_secret_gen<R: Rng + CryptoRng>(
        party_id: PartyId,
        rng: &mut R,
    ) -> eyre::Result<(Arc<TestSecretManager>, DLogSecretGenService)> {
        let secret_manager = Arc::new(TestSecretManager::new(
            PeerPrivateKey::from(ark_babyjubjub::Fr::rand(rng)),
            HashMap::new(),
        ));
        let secret_manager_ = Arc::clone(&secret_manager);
        let crypto_device = Arc::new(CryptoDevice::init(secret_manager).await?);
        let dlog_secret_gen = DLogSecretGenService::init(party_id, crypto_device);
        Ok((secret_manager_, dlog_secret_gen))
    }

    #[tokio::test]
    async fn test_secret_gen() -> eyre::Result<()> {
        let mut rng = rand::thread_rng();
        let rp_id = RpId::new(rng.r#gen());
        let degree = 1;
        let (secret_manager0, mut dlog_secret_gen0) =
            secret_manager_and_dlog_secret_gen(PartyId::from(0), &mut rng).await?;
        let (secret_manager1, mut dlog_secret_gen1) =
            secret_manager_and_dlog_secret_gen(PartyId::from(1), &mut rng).await?;
        let (secret_manager2, mut dlog_secret_gen2) =
            secret_manager_and_dlog_secret_gen(PartyId::from(2), &mut rng).await?;

        let dlog_secret_gen0_round1 = dlog_secret_gen0.round1(rp_id, degree);
        let dlog_secret_gen1_round1 = dlog_secret_gen1.round1(rp_id, degree);
        let dlog_secret_gen2_round1 = dlog_secret_gen2.round1(rp_id, degree);

        let round1_contributions = vec![
            dlog_secret_gen0_round1.contribution,
            dlog_secret_gen1_round1.contribution,
            dlog_secret_gen2_round1.contribution,
        ];
        let should_public_key = round1_contributions.iter().fold(
            ark_babyjubjub::EdwardsAffine::zero(),
            |acc, contribution| (acc + contribution.comm_share).into_affine(),
        );
        let peers = round1_contributions
            .iter()
            .map(|contribution| contribution.sender)
            .collect::<Vec<_>>();

        let dlog_secret_gen0_round2 =
            dlog_secret_gen0.round2(rp_id, PeerPublicKeyList::from(peers.clone()));
        let dlog_secret_gen1_round2 =
            dlog_secret_gen1.round2(rp_id, PeerPublicKeyList::from(peers.clone()));
        let dlog_secret_gen2_round2 =
            dlog_secret_gen2.round2(rp_id, PeerPublicKeyList::from(peers.clone()));

        let ciphers: Vec<Vec<_>> = (0..3)
            .map(|i| {
                vec![
                    dlog_secret_gen0_round2
                        .contribution
                        .get_cipher_text(PartyId::from(i))
                        .unwrap(),
                    dlog_secret_gen1_round2
                        .contribution
                        .get_cipher_text(PartyId::from(i))
                        .unwrap(),
                    dlog_secret_gen2_round2
                        .contribution
                        .get_cipher_text(PartyId::from(i))
                        .unwrap(),
                ]
            })
            .collect();
        let [ciphers0, ciphers1, ciphers2] = ciphers.try_into().expect("len is 3");

        dlog_secret_gen0
            .finalize(
                rp_id,
                k256::SecretKey::random(&mut rng).public_key(),
                round1_contributions.clone(),
                ciphers0,
            )
            .await;
        dlog_secret_gen1
            .finalize(
                rp_id,
                k256::SecretKey::random(&mut rng).public_key(),
                round1_contributions.clone(),
                ciphers1,
            )
            .await;
        dlog_secret_gen2
            .finalize(
                rp_id,
                k256::SecretKey::random(&mut rng).public_key(),
                round1_contributions.clone(),
                ciphers2,
            )
            .await;

        let dlog_secret0 = *secret_manager0
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .unwrap();
        let dlog_secret1 = *secret_manager1
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .unwrap();
        let dlog_secret2 = *secret_manager2
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .unwrap();

        let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
        let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
            &[
                dlog_secret0.into(),
                dlog_secret1.into(),
                dlog_secret2.into(),
            ],
            &lagrange,
        );

        let is_public_key =
            (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

        assert_eq!(is_public_key, should_public_key);

        Ok(())
    }
}
