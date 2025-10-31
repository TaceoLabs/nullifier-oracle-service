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

use eyre::{Context, ContextCompat};
use oprf_core::keys::keygen::KeyGenPoly;
use oprf_types::{
    RpId,
    chain::{
        SecretGenRound1Contribution, SecretGenRound2Contribution, SecretGenRound3Contribution,
    },
    crypto::{RpNullifierKey, RpSecretGenCiphertext, RpSecretGenCommitment},
};
use oprf_zk::Groth16Material;
use tracing::instrument;

use crate::services::crypto_device::{CryptoDevice, DLogShare};

/// Service for managing the distributed secret generation protocol.
///
/// Handles round 1 and round 2 of secret generation, and finalizes
/// by producing the party's share of the secret.
///
/// **Note:** Must only be used in a single-owner context. Do not share across tasks.
pub(crate) struct DLogSecretGenService {
    round1: HashMap<RpId, KeyGenPoly>,
    finished_shares: HashMap<RpId, DLogShare>,
    crypto_device: Arc<CryptoDevice>,
    key_gen_material: Groth16Material,
}

impl DLogSecretGenService {
    /// Initializes a new DLog secret generation service.
    pub(crate) fn init(
        crypto_device: Arc<CryptoDevice>,
        key_gen_material: Groth16Material,
    ) -> Self {
        Self {
            crypto_device,
            round1: HashMap::new(),
            finished_shares: HashMap::new(),
            key_gen_material,
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
    pub(crate) fn round1(&mut self, rp_id: RpId, threshold: u16) -> SecretGenRound1Contribution {
        tracing::info!("secret gen round1..");
        let mut rng = rand::thread_rng();
        let degree = usize::from(threshold - 1);
        let poly = KeyGenPoly::keygen(&mut rng, degree);
        let contribution = RpSecretGenCommitment {
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
        }
    }

    /// Executes round 2 of the secret generation protocol.
    ///
    /// Generates secret shares for all peers based on the polynomial generated in round 1
    /// and a proof of the encryptions.
    /// Returns a [`SecretGenRound2Contribution`] containing ciphertexts for all parties + the proof.
    ///
    /// # Arguments
    /// * `rp_id` - Identifier of the RP for which the secret is being generated.
    /// * `peers` - List of public keys for peers participating in the protocol.
    pub(crate) fn round2(&mut self, rp_id: RpId) -> eyre::Result<SecretGenRound2Contribution> {
        let my_poly = self.round1.remove(&rp_id).expect("todo how to handle this");
        let contribution = self
            .crypto_device
            .compute_keygen_proof_max_degree1_parties3(&self.key_gen_material, &my_poly)
            .context("while computing proof for round2")?;
        Ok(SecretGenRound2Contribution {
            rp_id,
            contribution,
        })
    }

    /// Finalizes secret generation by decrypting received ciphertexts and
    /// computing the final secret share for this party.
    ///
    /// The resulting share is registered in the [`CryptoDevice`] for later use.
    ///
    /// # Arguments
    /// * `rp_id` - Identifier of the RP for which the secret is being finalized.
    /// * `ciphers` - Ciphertexts received from other parties in round 2.
    #[instrument(level = "info", skip(self, ciphers))]
    pub(crate) fn round3(
        &mut self,
        rp_id: RpId,
        ciphers: Vec<RpSecretGenCiphertext>,
    ) -> eyre::Result<SecretGenRound3Contribution> {
        tracing::info!("calling round3 with {}", ciphers.len());
        let share = self
            .crypto_device
            .decrypt_key_gen_ciphertexts(ciphers)
            .context("while computing DLogShare")?;
        // We need to store the computed share - as soon as we get ready
        // event, we will store the share inside the crypto-device.
        self.finished_shares.insert(rp_id, share);
        Ok(SecretGenRound3Contribution { rp_id })
    }

    #[instrument(level = "info", skip(self, rp_public_key, rp_nullifier_key))]
    pub(crate) async fn finalize(
        &mut self,
        rp_id: RpId,
        rp_public_key: k256::PublicKey,
        rp_nullifier_key: RpNullifierKey,
    ) -> eyre::Result<()> {
        tracing::info!("calling finalize");
        let dlog_share = self
            .finished_shares
            .remove(&rp_id)
            .context("cannot find computed DLogShare")?;
        self.crypto_device
            .register_nullifier_share(rp_id, rp_public_key.into(), rp_nullifier_key, dlog_share)
            .await
            .context("while persisting DLogShare")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ark_ec::{CurveGroup as _, PrimeGroup};
    use ark_ff::UniformRand as _;
    use itertools::Itertools;
    use oprf_types::{
        ShareEpoch,
        crypto::{PeerPublicKey, PeerPublicKeyList, RpSecretGenCiphertexts},
    };
    use rand::Rng;

    use crate::services::{crypto_device::PeerPrivateKey, secret_manager::test::TestSecretManager};

    use super::*;

    async fn secret_manager_and_dlog_secret_gen(
        private_key: PeerPrivateKey,
        public_key_list: PeerPublicKeyList,
        key_gen_material: Groth16Material,
    ) -> eyre::Result<(Arc<TestSecretManager>, DLogSecretGenService)> {
        let secret_manager = Arc::new(TestSecretManager::new(private_key, HashMap::new()));
        let secret_manager_ = Arc::clone(&secret_manager);
        let crypto_device = Arc::new(CryptoDevice::init(secret_manager, public_key_list).await?);
        let dlog_secret_gen = DLogSecretGenService::init(crypto_device, key_gen_material);
        Ok((secret_manager_, dlog_secret_gen))
    }

    fn build_public_inputs(
        degree: u16,
        pk: PeerPublicKey,
        contribution: &RpSecretGenCiphertexts,
        peer_keys_flattened: &[ark_bn254::Fr],
        commitments: RpSecretGenCommitment,
    ) -> Vec<ark_babyjubjub::Fq> {
        // public input is:
        // 1) PublicKey from sender (Affine Point Babyjubjub)
        // 2) Commitment to share (Affine Point Babyjubjub)
        // 3) Commitment to coeffs (Basefield Babyjubjub)
        // 4) Ciphertexts for peers (in this case 3 Basefield BabyJubJub)
        // 5) Commitments to plaintexts (in this case 3 Affine Points BabyJubJub)
        // 6) Degree (Basefield BabyJubJub)
        // 7) Public Keys from peers (in this case 3 Affine Points BabyJubJub)
        // 8) Nonces (in this case 3 Basefield BabyJubJub)
        let mut ciphers = Vec::with_capacity(3);
        let mut comm_ciphers = Vec::with_capacity(3);
        let mut nonces = Vec::with_capacity(3);
        for cipher in contribution.ciphers.iter() {
            ciphers.push(cipher.cipher);
            comm_ciphers.push(cipher.commitment.x);
            comm_ciphers.push(cipher.commitment.y);
            nonces.push(cipher.nonce);
        }
        let mut public_inputs = Vec::with_capacity(24);
        public_inputs.push(pk.inner().x);
        public_inputs.push(pk.inner().y);
        public_inputs.push(commitments.comm_share.x);
        public_inputs.push(commitments.comm_share.y);
        public_inputs.push(commitments.comm_coeffs);
        public_inputs.extend(ciphers);
        public_inputs.extend(comm_ciphers);
        public_inputs.push(ark_babyjubjub::Fq::from(degree));
        public_inputs.extend(peer_keys_flattened.iter());
        public_inputs.extend(nonces);
        public_inputs
    }

    #[tokio::test]
    async fn test_secret_gen() -> eyre::Result<()> {
        let mut rng = rand::thread_rng();
        let rp_id = RpId::new(rng.r#gen());
        let threshold = 2;
        let graph =
            PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../circom/keygen_graph.bin");
        let graph = std::fs::read(graph)?;
        let key_gen_zkey =
            PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../circom/keygen_13.zkey");
        let key_gen_zkey = std::fs::read(key_gen_zkey)?;
        let key_gen_material = Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?;

        let sk0 = PeerPrivateKey::from(ark_babyjubjub::Fr::rand(&mut rng));
        let sk1 = PeerPrivateKey::from(ark_babyjubjub::Fr::rand(&mut rng));
        let sk2 = PeerPrivateKey::from(ark_babyjubjub::Fr::rand(&mut rng));

        let peers = PeerPublicKeyList::from(vec![
            sk0.get_public_key(),
            sk1.get_public_key(),
            sk2.get_public_key(),
        ]);

        let (secret_manager0, mut dlog_secret_gen0) = secret_manager_and_dlog_secret_gen(
            sk0,
            peers.clone(),
            Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?,
        )
        .await?;
        let (secret_manager1, mut dlog_secret_gen1) = secret_manager_and_dlog_secret_gen(
            sk1,
            peers.clone(),
            Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?,
        )
        .await?;
        let (secret_manager2, mut dlog_secret_gen2) = secret_manager_and_dlog_secret_gen(
            sk2,
            peers.clone(),
            Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?,
        )
        .await?;

        let dlog_secret_gen0_round1 = dlog_secret_gen0.round1(rp_id, threshold);
        let dlog_secret_gen1_round1 = dlog_secret_gen1.round1(rp_id, threshold);
        let dlog_secret_gen2_round1 = dlog_secret_gen2.round1(rp_id, threshold);

        let commitments0 = dlog_secret_gen0_round1.contribution.clone();
        let commitments1 = dlog_secret_gen1_round1.contribution.clone();
        let commitments2 = dlog_secret_gen2_round1.contribution.clone();

        let round1_contributions = [
            dlog_secret_gen0_round1.contribution,
            dlog_secret_gen1_round1.contribution,
            dlog_secret_gen2_round1.contribution,
        ];
        let should_public_key = round1_contributions.iter().fold(
            ark_babyjubjub::EdwardsAffine::zero(),
            |acc, contribution| (acc + contribution.comm_share).into_affine(),
        );

        let peer_keys_flattened = peers
            .clone()
            .into_iter()
            .flat_map(|p| [p.inner().x, p.inner().y])
            .collect_vec();

        let dlog_secret_gen0_round2 = dlog_secret_gen0
            .round2(rp_id)
            .context("while doing round2")?;
        let dlog_secret_gen1_round2 = dlog_secret_gen1
            .round2(rp_id)
            .context("while doing round2")?;
        let dlog_secret_gen2_round2 = dlog_secret_gen2
            .round2(rp_id)
            .context("while doing round2")?;

        assert_eq!(dlog_secret_gen0_round2.rp_id, rp_id);
        assert_eq!(dlog_secret_gen1_round2.rp_id, rp_id);
        assert_eq!(dlog_secret_gen2_round2.rp_id, rp_id);
        let peer_keys = peers.clone().into_inner();
        // verify the proofs
        // build public inputs for proof0
        let public_inputs0 = build_public_inputs(
            threshold - 1,
            peer_keys[0],
            &dlog_secret_gen0_round2.contribution,
            &peer_keys_flattened,
            commitments0,
        );
        let public_inputs1 = build_public_inputs(
            threshold - 1,
            peer_keys[1],
            &dlog_secret_gen1_round2.contribution,
            &peer_keys_flattened,
            commitments1,
        );
        let public_inputs2 = build_public_inputs(
            threshold - 1,
            peer_keys[2],
            &dlog_secret_gen2_round2.contribution,
            &peer_keys_flattened,
            commitments2,
        );
        let proof0 = dlog_secret_gen0_round2.contribution.proof;
        let proof1 = dlog_secret_gen1_round2.contribution.proof;
        let proof2 = dlog_secret_gen2_round2.contribution.proof;
        key_gen_material.verify_proof(&proof0.into(), &public_inputs0)?;
        key_gen_material.verify_proof(&proof1.into(), &public_inputs1)?;
        key_gen_material.verify_proof(&proof2.into(), &public_inputs2)?;

        let ciphers = (0..3)
            .map(|i| {
                vec![
                    dlog_secret_gen0_round2.contribution.ciphers[i].clone(),
                    dlog_secret_gen1_round2.contribution.ciphers[i].clone(),
                    dlog_secret_gen2_round2.contribution.ciphers[i].clone(),
                ]
            })
            .collect_vec();
        let [ciphers0, ciphers1, ciphers2] = ciphers.try_into().expect("len is 3");

        let dlog_secret_gen0_round3 = dlog_secret_gen0.round3(rp_id, ciphers0)?;
        let dlog_secret_gen1_round3 = dlog_secret_gen1.round3(rp_id, ciphers1)?;
        let dlog_secret_gen2_round3 = dlog_secret_gen2.round3(rp_id, ciphers2)?;
        assert_eq!(dlog_secret_gen0_round3.rp_id, rp_id);
        assert_eq!(dlog_secret_gen1_round3.rp_id, rp_id);
        assert_eq!(dlog_secret_gen2_round3.rp_id, rp_id);

        let share0 = dlog_secret_gen0
            .finished_shares
            .get(&rp_id)
            .expect("gen0 has no share")
            .clone();
        let share1 = dlog_secret_gen1
            .finished_shares
            .get(&rp_id)
            .expect("gen0 has no share")
            .clone();
        let share2 = dlog_secret_gen2
            .finished_shares
            .get(&rp_id)
            .expect("gen0 has no share")
            .clone();

        let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
        let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
            &[share0.into(), share1.into(), share2.into()],
            &lagrange,
        );

        let is_public_key =
            (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

        assert_eq!(is_public_key, should_public_key);

        let rp_public_key = k256::SecretKey::random(&mut rng).public_key();
        // finalize round
        dlog_secret_gen0
            .finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))
            .await?;
        dlog_secret_gen1
            .finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))
            .await?;
        dlog_secret_gen2
            .finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))
            .await?;

        let dlog_secret0 = secret_manager0
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .cloned()
            .unwrap();
        let dlog_secret1 = secret_manager1
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .cloned()
            .unwrap();
        let dlog_secret2 = secret_manager2
            .rp_materials
            .lock()
            .get(&rp_id)
            .unwrap()
            .shares
            .get(&ShareEpoch::default())
            .cloned()
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
        // check that shares are removed correctly
        assert!(!dlog_secret_gen0.finished_shares.contains_key(&rp_id));
        assert!(!dlog_secret_gen1.finished_shares.contains_key(&rp_id));
        assert!(!dlog_secret_gen2.finished_shares.contains_key(&rp_id));

        Ok(())
    }
}
