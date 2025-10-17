use std::ops::Shr;
use std::{collections::HashMap, path::Path, sync::Arc};

use ark_bn254::Bn254;
use ark_ff::{AdditiveGroup, BigInt, Field as _, UniformRand as _};
use circom_types::{groth16::ZKey, traits::CheckElement};
use eyre::Context as _;
use groth16::{CircomReduction, ConstraintMatrices, Groth16, Proof, ProvingKey};
use itertools::{Itertools as _, izip};
use oprf_core::keys::keygen::KeyGenPoly;
use oprf_types::crypto::{RpSecretGenCiphertext, RpSecretGenCiphertexts};
use tracing::instrument;
use witness::{BlackBoxFunction, Graph, ruint::aliases::U256};

use crate::services::crypto_device::CryptoDevice;

// TODO maybe we can unify this with the OPRF-client material?
pub(super) struct Groth16Material {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<ark_bn254::Fr>,
    graph: Graph,
}

impl Groth16Material {
    pub(crate) fn from_paths(
        zkey_path: impl AsRef<Path>,
        graph_path: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        let graph_bytes =
            std::fs::read(graph_path).context("while loading witness graph from file")?;
        let graph = witness::init_graph(&graph_bytes).context("while parsing witness graph")?;

        let zkey_bytes = std::fs::read(zkey_path).context("while loading zkey from file")?;

        let zkey = ZKey::from_reader(zkey_bytes.as_slice(), CheckElement::No)
            .context("while parsing zkey")?;
        let (matrices, pk) = zkey.into();
        Ok(Self {
            matrices,
            pk,
            graph,
        })
    }
}

pub(super) fn black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();
    bbfs.insert(
        "bbf_inv".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bb_finv(in) {
            //     return in!=0 ? 1/in : 0;
            // }
            args[0].inverse().unwrap_or(ark_bn254::Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_num_2_bits_helper".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bbf_num_2_bits_helper(in, i) {
            //     return (in >> i) & 1;
            // }
            let a: U256 = args[0].into();
            let b: U256 = args[1].into();
            let ls_limb = b.as_limbs()[0];
            ark_bn254::Fr::new((a.shr(ls_limb as usize) & U256::from(1)).into())
        }),
    );
    bbfs
}

impl CryptoDevice {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn compute_keygen_proof_max_degree1_parties3(
        &self,
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

        let Groth16Material {
            pk,
            matrices,
            graph,
        } = &self.key_gen_zk_material;

        let witness = witness::calculate_witness(inputs, graph, Some(&self.bbfs))
            .context("while doing witness extension")?
            .into_iter()
            .map(|v| ark_bn254::Fr::from(BigInt(v.into_limbs())))
            .collect_vec();

        // proof
        let mut rng = rand::thread_rng();
        let r = ark_bn254::Fr::rand(&mut rng);
        let s = ark_bn254::Fr::rand(&mut rng);
        let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, &witness)
            .context("while computing key-gen proof")?;

        let public_inputs =
            witness[1..self.key_gen_zk_material.matrices.num_instance_variables].to_vec();

        self.verify_keygen_proof_max_degree1_parties3(&proof, &public_inputs)
            .context("cannot verify my proof")?;

        // parse the outputs from the public_input
        let pk_computed = ark_babyjubjub::EdwardsAffine::new(public_inputs[0], public_inputs[1]);
        // parse commitment to share
        let comm_share_computed =
            ark_babyjubjub::EdwardsAffine::new(public_inputs[2], public_inputs[3]);

        // parse commitment to coefficients
        let comm_coeffs_computed = ark_babyjubjub::Fq::from(public_inputs[4]);

        let ciphertexts = public_inputs[5..=7]
            .iter()
            .map(|x| ark_babyjubjub::Fq::from(*x));

        let comm_plains = public_inputs[8..=13]
            .chunks_exact(2)
            .map(|coords| ark_babyjubjub::EdwardsAffine::new(coords[0], coords[1]));

        let rp_ciphertexts = izip!(ciphertexts, comm_plains, nonces)
            .map(|(cipher, comm, nonce)| RpSecretGenCiphertext::new(cipher, comm, nonce))
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

    pub(crate) fn verify_keygen_proof_max_degree1_parties3(
        &self,
        proof: &Proof<Bn254>,
        public_inputs: &[ark_bn254::Fr],
    ) -> eyre::Result<()> {
        Groth16::verify(&self.key_gen_zk_material.pk.vk, proof, public_inputs)
            .context("while verifying KeyGen13 proof")
    }
}
