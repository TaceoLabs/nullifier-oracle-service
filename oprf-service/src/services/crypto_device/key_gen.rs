use std::collections::HashMap;

use ark_ff::{BigInt, UniformRand as _};
use eyre::Context;
use groth16::{CircomReduction, Groth16};
use itertools::{Itertools as _, izip};
use oprf_core::keys::keygen::KeyGenPoly;
use oprf_types::crypto::{RpSecretGenCiphertext, RpSecretGenCiphertexts};
use oprf_zk::Groth16Material;
use tracing::instrument;
use witness::ruint::aliases::U256;

use crate::services::crypto_device::CryptoDevice;

impl CryptoDevice {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn compute_keygen_proof_max_degree1_parties3(
        &self,
        key_gen_material: &Groth16Material,
        poly: &KeyGenPoly,
    ) -> eyre::Result<RpSecretGenCiphertexts> {
        // check that degree is 1 and num_parties is 3
        let pks = self.public_key_list.clone().into_inner();
        if pks.len() != 3 {
            eyre::bail!("only can do num_parties 3");
        }
        // check that all keys are valid BabyJubJub points and in the correct subgroup
        for (party_id, pk) in pks.iter().enumerate() {
            let p = pk.inner();
            if !p.is_on_curve() {
                eyre::bail!("PublicKey from {party_id} is not on curve!");
            }
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                eyre::bail!("PublicKey from {party_id} is not in correct subgroup!");
            }
        }
        // compute the nonces for every party
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

        let coeffs = poly
            .coeffs()
            .iter()
            .map(|coeff| coeff.into())
            .collect::<Vec<U256>>();

        // build the input for the graph
        let mut inputs = HashMap::new();
        inputs.insert(String::from("degree"), vec![U256::from(poly.degree())]);
        inputs.insert(String::from("my_sk"), vec![self.private_key.inner().into()]);
        inputs.insert(String::from("pks"), pks);
        inputs.insert(String::from("poly"), coeffs);
        inputs.insert(
            String::from("nonces"),
            nonces.iter().map(|n| n.into()).collect_vec(),
        );

        let witness = witness::calculate_witness(
            inputs,
            &key_gen_material.graph,
            Some(&key_gen_material.bbfs),
        )
        .context("while doing witness extension")?
        .into_iter()
        .map(|v| ark_bn254::Fr::from(BigInt(v.into_limbs())))
        .collect_vec();

        // proof
        let mut rng = rand::thread_rng();
        let r = ark_bn254::Fr::rand(&mut rng);
        let s = ark_bn254::Fr::rand(&mut rng);
        let proof = Groth16::prove::<CircomReduction>(
            &key_gen_material.pk,
            r,
            s,
            &key_gen_material.matrices,
            &witness,
        )
        .context("while computing key-gen proof")?;

        let public_inputs = witness[1..key_gen_material.matrices.num_instance_variables].to_vec();

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
            .map(|(cipher, comm, nonce)| RpSecretGenCiphertext::new(*cipher, comm, nonce))
            .collect_vec();

        if pk_computed != self.private_key.get_public_key().inner() {
            eyre::bail!("computed public key does not match with my own!");
        }

        if comm_share_computed != poly.get_pk_share() {
            eyre::bail!("computed commitment to share does not match with my own!");
        }

        if comm_coeffs_computed != poly.get_coeff_commitment() {
            eyre::bail!("computed commitment to coeffs does not match with my own!");
        }

        Ok(RpSecretGenCiphertexts::new(proof.into(), rp_ciphertexts))
    }
}
