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

use ark_ff::UniformRand;
use oprf_core::keys::keygen::KeyGenPoly;
use oprf_types::{
    RpId,
    chain::{SecretGenRound1Contribution, SecretGenRound2Contribution},
    crypto::{
        PartyId, PeerPublicKeyList, RpSecretGenCiphertext, RpSecretGenCiphertexts,
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
    #[instrument(level = "info", skip(self, ciphers))]
    pub(crate) fn finalize(&self, rp_id: RpId, ciphers: Vec<RpSecretGenCiphertext>) {
        tracing::info!("calling finalize with {}", ciphers.len());
        let shares = ciphers
            .into_iter()
            .map(|x| self.crypto_device.decrypt_key_gen_ciphertext(x))
            .collect::<eyre::Result<Vec<_>>>()
            .expect("TODO");
        let my_share = KeyGenPoly::accumulate_shares(&shares);
        self.crypto_device
            .register_nullifier_share(rp_id, DLogShare::from(my_share))
            .expect("TODO");
        tracing::info!("my share: {my_share}");
    }
}
