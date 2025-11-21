//! This service handles the distributed secret generation protocol for RPs.
//! It maintains toxic waste for ongoing key generation rounds. The service handles the destruction of this toxic waste during the lifecycle of key generation.
//!
//! Currently, there is no timeout for a single key generation. Therefore, the toxic waste will not be cleaned up and will remain in memory.
//!
//! On the other hand, the toxic waste is not persisted anywhere other than RAM. This means that if an OPRF peer shuts down during key generation, the key generation cannot be completed, as the data is lost.
//!
//! **Important:** This service is **not thread-safe**. It is intended to be used
//! only in contexts where a single dedicated task owns the struct. No internal
//! locking (`Mutex`) or reference counting (`Arc`) is performed, so multiple tasks
//! must not concurrently access it.
//!
//! We refer to [Appendix B.2 of our design document](https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/docs/oprf.pdf) for more information about the OPRF-nullifier
//! generation protocol.

use std::collections::HashMap;

use alloy::primitives::U256;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use eyre::{Context, ContextCompat};
use groth16_material::circom::CircomGroth16Material;
use itertools::{Itertools as _, izip};
use oprf_core::{
    ddlog_equality::shamir::DLogShareShamir,
    keygen::{self, KeyGenPoly},
};
use oprf_types::{
    OprfKeyId,
    chain::{
        SecretGenRound1Contribution, SecretGenRound2Contribution, SecretGenRound3Contribution,
    },
    crypto::{
        EphemeralEncryptionPublicKey, OprfPublicKey, PeerPublicKeyList, SecretGenCiphertext,
        SecretGenCiphertexts, SecretGenCommitment,
    },
};
use rand::{CryptoRng, Rng};
use tracing::instrument;
use zeroize::ZeroizeOnDrop;

use crate::services::{
    oprf_key_material_store::OprfKeyMaterialStore, secret_manager::StoreDLogShare,
};

#[cfg(test)]
mod tests;

/// Service for managing the distributed secret generation protocol.
///
/// Handles round 1 and round 2 of secret generation, and finalizes
/// by producing the party's share of the secret.
///
/// **Note:** Must only be used in a single-owner context. Do not share across tasks.
pub(crate) struct DLogSecretGenService {
    toxic_waste_round1: HashMap<OprfKeyId, ToxicWasteRound1>,
    toxic_waste_round2: HashMap<OprfKeyId, ToxicWasteRound2>,
    finished_shares: HashMap<OprfKeyId, DLogShareShamir>,
    key_gen_material: CircomGroth16Material,
    oprf_key_material_store: OprfKeyMaterialStore,
}

/// The ephemeral private key of an OPRF peer.
///
/// Used internally to compute Diffie-Hellman for key-generation operations.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
/// **Note**: Don't reuse a key. One key per keygen.
#[derive(ZeroizeOnDrop)]
struct PeerPrivateKey(ark_babyjubjub::Fr);

/// The toxic waste generated in round 1 of the key generation protocol.
///
/// Contains the full polynomial and the ephemeral private key for a single key generation.
struct ToxicWasteRound1 {
    poly: KeyGenPoly,
    sk: PeerPrivateKey,
}

/// The toxic waste generated in round 2 of the key generation protocol.
///
/// Contains the ephemeral private key for a single key generation and the associated public keys of all peers.
/// The public key list is not toxic waste per se, but for simplicity we store it together with the private key.
struct ToxicWasteRound2 {
    peers: PeerPublicKeyList,
    sk: PeerPrivateKey,
}

impl PeerPrivateKey {
    /// Generates a fresh private-key to be used in a single DLog generation.
    /// **Note**: do not reuse this key.
    fn generate<R: Rng + CryptoRng>(r: &mut R) -> Self {
        Self(ark_babyjubjub::Fr::rand(r))
    }
    /// Computes the associated [`EphemeralEncryptionPublicKey`] by multiplying the private key with the generator.
    pub fn get_public_key(&self) -> EphemeralEncryptionPublicKey {
        EphemeralEncryptionPublicKey::new_unchecked(
            (ark_babyjubjub::EdwardsAffine::generator() * self.0).into_affine(),
        )
    }

    /// Returns the inner scalar value of the private key.
    pub fn inner(&self) -> &ark_babyjubjub::Fr {
        &self.0
    }
}

impl ToxicWasteRound1 {
    /// Creates a new instance of `ToxicWasteRound1`.
    ///
    /// Generates a secret-sharing polynomial and an ephemeral private key for the first round of the key generation protocol.
    ///
    /// **Note:** do not reuse the toxic waste.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomial to be generated (relates to threshold settings).
    /// * `rng` - A mutable reference to a cryptographically secure random number generator.
    fn new<R: Rng + CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let poly = KeyGenPoly::new(rng, degree);
        let sk = PeerPrivateKey::generate(rng);
        Self { poly, sk }
    }

    /// Advances to the second round of key generation.
    ///
    /// Consumes `self` and combines the secret material from round one with the public keys of all peers.
    ///
    /// **Note:** do not reuse the toxic waste.
    ///
    /// # Arguments
    ///
    /// * `peers` - A list of public keys for all peers involved in the key generation session.
    ///
    /// # Returns
    ///
    /// A `ToxicWasteRound2` instance containing the ephemeral private key and the peer public key list.
    fn next(self, peers: PeerPublicKeyList) -> ToxicWasteRound2 {
        ToxicWasteRound2 { peers, sk: self.sk }
    }
}

impl DLogSecretGenService {
    /// Initializes a new DLog secret generation service.
    pub(crate) fn init(
        oprf_key_material_store: OprfKeyMaterialStore,
        key_gen_material: CircomGroth16Material,
    ) -> Self {
        Self {
            toxic_waste_round1: HashMap::new(),
            toxic_waste_round2: HashMap::new(),
            finished_shares: HashMap::new(),
            key_gen_material,
            oprf_key_material_store,
        }
    }

    /// Deletes all material associated with the [`OprfKeyId`].
    /// This includes:
    /// * [`ToxicWasteRound1`]
    /// * [`ToxicWasteRound2`]
    /// * Any finished shares that wait for finalize from all peers
    /// * The [`crate::services::oprf_key_material_store::OprfKeyMaterial`] in the [`OprfKeyMaterialStore`].
    pub(crate) fn delete_oprf_key_material(&mut self, oprf_key_id: OprfKeyId) {
        if self.toxic_waste_round1.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} toxic waste round 1 from secret-gen");
        };
        if self.toxic_waste_round2.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} toxic waste round 2 from secret-gen");
        };
        if self.finished_shares.remove(&oprf_key_id).is_some() {
            tracing::debug!("removed {oprf_key_id:?} finished share from secret-gen");
        };
        self.oprf_key_material_store.remove(oprf_key_id);
    }

    /// Executes round 1 of the secret generation protocol.
    ///
    /// Generates a polynomial of the specified degree and stores it internally.
    /// Returns a [`SecretGenRound1Contribution`] containing the commitment to share with other parties.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `threshold` - The threshold of the MPC-protocol.
    #[instrument(level = "info", skip(self))]
    pub(crate) fn round1(
        &mut self,
        oprf_key_id: OprfKeyId,
        threshold: u16,
    ) -> SecretGenRound1Contribution {
        tracing::info!("secret gen round1..");
        let mut rng = rand::thread_rng();
        let degree = usize::from(threshold - 1);
        let toxic_waste = ToxicWasteRound1::new(degree, &mut rng);
        let contribution = SecretGenCommitment {
            comm_share: toxic_waste.poly.get_pk_share(),
            comm_coeffs: toxic_waste.poly.get_coeff_commitment(),
            eph_pub_key: toxic_waste.sk.get_public_key(),
        };
        let old_value = self.toxic_waste_round1.insert(oprf_key_id, toxic_waste);
        // TODO handle this more gracefully
        assert!(
            old_value.is_none(),
            "already had this round1 - this is a bug"
        );
        SecretGenRound1Contribution {
            oprf_key_id,
            contribution,
        }
    }

    /// Executes round 2 of the secret generation protocol.
    ///
    /// Generates secret shares for all peers based on the polynomial generated in round 1 and a proof of the encryptions.
    ///
    /// Returns a [`SecretGenRound2Contribution`] containing ciphertexts for all parties + the proof.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `peers` - List of public keys for peers participating in the protocol.
    pub(crate) fn round2(
        &mut self,
        oprf_key_id: OprfKeyId,
        peers: PeerPublicKeyList,
    ) -> eyre::Result<SecretGenRound2Contribution> {
        // check that degree is 1 and num_parties is 3
        if peers.len() != 3 {
            eyre::bail!("only can do num_parties 3");
        }
        let toxic_waste_r1 = self
            .toxic_waste_round1
            .remove(&oprf_key_id)
            .expect("todo how to handle this");
        let (contribution, toxix_waste_r2) = compute_keygen_proof_max_degree1_parties3(
            &self.key_gen_material,
            toxic_waste_r1,
            peers,
        )
        .context("while computing proof for round2")?;
        self.toxic_waste_round2.insert(oprf_key_id, toxix_waste_r2);
        Ok(SecretGenRound2Contribution {
            oprf_key_id,
            contribution,
        })
    }

    /// Finalizes secret generation by decrypting received ciphertexts and
    /// computing the final secret share for this party.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the OPRF key that we generate.
    /// * `ciphers` - Ciphertexts received from other parties in round 2.
    #[instrument(level = "info", skip(self, ciphers))]
    pub(crate) fn round3(
        &mut self,
        oprf_key_id: OprfKeyId,
        ciphers: Vec<SecretGenCiphertext>,
    ) -> eyre::Result<SecretGenRound3Contribution> {
        tracing::info!("calling round3 with {}", ciphers.len());
        let toxic_waste_r2 = self
            .toxic_waste_round2
            .remove(&oprf_key_id)
            .expect("todo what if not here?");
        let share = decrypt_key_gen_ciphertexts(ciphers, toxic_waste_r2)
            .context("while computing DLogShare")?;
        // We need to store the computed share - as soon as we get ready
        // event, we will store the share inside the crypto-device.
        self.finished_shares.insert(oprf_key_id, share);
        Ok(SecretGenRound3Contribution { oprf_key_id })
    }

    /// Marks the generated secret as finished and stores it to the [`OprfKeyMaterialStore`] along with its public key.
    ///
    /// # Arguments
    /// * `oprf_key_id` - Identifier of the RP for which the secret is being finalized.
    /// * `oprf_public_key` - The public point P of the created secret x, where P=xG and G is the generator of BabyJubJub.
    #[instrument(level = "info", skip(self, oprf_public_key))]
    pub(crate) fn finalize(
        &mut self,
        oprf_key_id: OprfKeyId,
        oprf_public_key: OprfPublicKey,
    ) -> eyre::Result<StoreDLogShare> {
        tracing::info!("calling finalize");
        let dlog_share = self
            .finished_shares
            .remove(&oprf_key_id)
            .context("cannot find computed DLogShare")?;
        self.oprf_key_material_store
            .add(oprf_key_id, oprf_public_key, dlog_share.clone());
        Ok(StoreDLogShare {
            oprf_key_id,
            oprf_public_key,
            share: dlog_share,
        })
    }
}

/// Decrypts a key-generation ciphertext using the private key.
///
/// Returns the share of the peer's polynomial or an error if decryption fails.
fn decrypt_key_gen_ciphertexts(
    ciphers: Vec<SecretGenCiphertext>,
    toxic_waste: ToxicWasteRound2,
) -> eyre::Result<DLogShareShamir> {
    let ToxicWasteRound2 { peers, sk } = toxic_waste;
    // In some later version, we maybe need some meaningful way
    // to tell which party produced a wrong ciphertext. Currently,
    // we trust the smart-contract to verify the proof, therefore
    // it should never happen that this here fails. If yes, there is
    // a bug.
    //
    // In some future version, we might have an optimistic approach
    // where we don't verify the proof and need to pinpoint the
    // scoundrel.
    let shares = ciphers
        .into_iter()
        .enumerate()
        .map(|(idx, cipher)| {
            let SecretGenCiphertext {
                nonce,
                cipher,
                commitment,
            } = cipher;
            let their_pk = peers[idx].inner();
            let share = keygen::decrypt_share(sk.inner(), their_pk, cipher, nonce)
                .context("cannot decrypt share ciphertext from peer")?;
            // check commitment
            let is_commitment = (ark_babyjubjub::EdwardsAffine::generator() * share).into_affine();
            // This is actually not possible if Smart Contract verified proof
            if is_commitment == commitment {
                eyre::Ok(share)
            } else {
                eyre::bail!("Commitment for {idx} wrong");
            }
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    Ok(DLogShareShamir::from(keygen::accumulate_shares(&shares)))
}

/// Executes the `KeyGen` circom circuit for degree 1 and 3 parties.
///
/// ## Security Considerations
/// This method expects that the parameter `peers` contains exactly three [`EphemeralEncryptionPublicKey`]s that encapsulate valid BabyJubJub points on the correct subgroup.
///
/// If `peers.len()` != 3, the method panics.
/// If `peers` were constructed without [`EphemeralEncryptionPublicKey::new_unchecked`], the points are on curve and the correct subgroup.
///
/// This method consumes an instance of [`ToxicWasteRound1`] and, on success, produces an instance of [`ToxicWasteRound2`]. This enforces that the toxic waste from round 1 is in fact dropped when continuing with the KeyGen protocol.
fn compute_keygen_proof_max_degree1_parties3(
    key_gen_material: &CircomGroth16Material,
    toxic_waste: ToxicWasteRound1,
    peers: PeerPublicKeyList,
) -> eyre::Result<(SecretGenCiphertexts, ToxicWasteRound2)> {
    // compute the nonces for every party
    assert_eq!(
        peers.len(),
        3,
        "amount peers must be checked before calling this function"
    );
    let pks = peers.clone().into_inner();
    let mut rng = rand::thread_rng();
    let nonces = (0..pks.len())
        .map(|_| ark_babyjubjub::Fq::rand(&mut rng))
        .collect_vec();

    let pks = pks
        .into_iter()
        .flat_map(|pk| {
            let p = pk.inner();
            [p.x.into(), p.y.into()]
        })
        .collect::<Vec<U256>>();

    let coeffs = toxic_waste
        .poly
        .coeffs()
        .iter()
        .map(|coeff| coeff.into())
        .collect::<Vec<U256>>();

    // build the input for the graph
    let mut inputs = HashMap::new();
    inputs.insert(
        String::from("degree"),
        vec![U256::from(toxic_waste.poly.degree())],
    );
    inputs.insert(String::from("my_sk"), vec![toxic_waste.sk.inner().into()]);
    inputs.insert(String::from("pks"), pks);
    inputs.insert(String::from("poly"), coeffs);
    inputs.insert(
        String::from("nonces"),
        nonces.iter().map(|n| n.into()).collect_vec(),
    );
    let (proof, public_inputs) = key_gen_material
        .generate_proof(&inputs, &mut rand::thread_rng())
        .context("while computing key-gen proof")?;

    key_gen_material
        .verify_proof(&proof, &public_inputs)
        .context("while verifying key gen proof")?;

    // parse the outputs from the public_input
    let pk_computed = ark_babyjubjub::EdwardsAffine::new(public_inputs[0], public_inputs[1]);
    // parse commitment to share
    let comm_share_computed =
        ark_babyjubjub::EdwardsAffine::new(public_inputs[2], public_inputs[3]);

    // parse commitment to coefficients
    let comm_coeffs_computed = public_inputs[4];

    let ciphertexts = public_inputs[5..=7].iter();

    let comm_plains = public_inputs[8..=13]
        .chunks_exact(2)
        .map(|coords| ark_babyjubjub::EdwardsAffine::new(coords[0], coords[1]));

    let rp_ciphertexts = izip!(ciphertexts, comm_plains, nonces)
        .map(|(cipher, comm, nonce)| SecretGenCiphertext::new(*cipher, comm, nonce))
        .collect_vec();

    if pk_computed != toxic_waste.sk.get_public_key().inner() {
        eyre::bail!("computed public key does not match with my own!");
    }

    if comm_share_computed != toxic_waste.poly.get_pk_share() {
        eyre::bail!("computed commitment to share does not match with my own!");
    }

    if comm_coeffs_computed != toxic_waste.poly.get_coeff_commitment() {
        eyre::bail!("computed commitment to coeffs does not match with my own!");
    }

    let ciphers = SecretGenCiphertexts::new(proof.into(), rp_ciphertexts);
    Ok((ciphers, toxic_waste.next(peers)))
}
