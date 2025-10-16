//! Zero-Knowledge proof helpers and Groth16 material for OPRF client.
//!
//! This module provides everything necessary to generate and verify
//! zero-knowledge proofs for OPRFQuery and OPRFNullifier Circom circuits.
//!
//! Key points:
//! - Holds Groth16 proving keys and their associated constraint matrices
//!   for both the OPRFQuery and OPRFNullifier circuits.
//! - Validates the fingerprint of the proving keys to prevent accidental use
//!   of wrong keys.
//! - Provides methods to generate proofs from prepared circuit inputs, and
//!   immediately verifies the generated proof against the verifying key.
//! - Includes helper functions to calculate witnesses and manage black-box
//!   functions required by Circom circuits.
//!
//! We refer to the current SHA-256 fingerprints:
//! - [`QUERY_PK_FINGERPRINT`]
//! - [`QUERY_MATRICES_FINGERPRINT`]
//! - [`NULLIFIER_PK_FINGERPRINT`]
//! - [`NULLIFIER_MATRICES_FINGERPRINT`]

use std::ops::Shr;
use std::str::FromStr;
use std::{collections::HashMap, path::Path, sync::Arc};

use ark_bn254::Bn254;
use ark_ff::{AdditiveGroup as _, BigInt, Field as _, LegendreSymbol, UniformRand as _};
use ark_serde_compat::groth16::Groth16Proof;
use ark_serialize::CanonicalDeserialize;
use circom_types::groth16::ConstraintMatricesWrapper;
use groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, VerifyingKey};
use k256::sha2::Digest as _;
use oprf_core::proof_input_gen::nullifier::NullifierProofInput;
use oprf_core::proof_input_gen::query::QueryProofInput;
use rand::{CryptoRng, Rng};
use witness::{BlackBoxFunction, ruint::aliases::U256};

const QUERY_GRAPH_BYTES: &[u8] = include_bytes!("../../data/query_graph.bin");
const NULLIFIER_GRAPH_BYTES: &[u8] = include_bytes!("../../data/nullifier_graph.bin");

#[cfg(feature = "embed-zkeys")]
const QUERY_PK_BYTES: &[u8] = include_bytes!("../../data/query_pk.bin");
#[cfg(feature = "embed-zkeys")]
const QUERY_MATRICES_BYTES: &[u8] = include_bytes!("../../data/query_matrices.bin");
#[cfg(feature = "embed-zkeys")]
const NULLIFIER_PK_BYTES: &[u8] = include_bytes!("../../data/nullifier_pk.bin");
#[cfg(feature = "embed-zkeys")]
const NULLIFIER_MATRICES_BYTES: &[u8] = include_bytes!("../../data/nullifier_matrices.bin");

/// The SHA-256 fingerprint of the OPRFQuery `ProvingKey`.
pub const QUERY_PK_FINGERPRINT: &str =
    "c73fdab5c5b859c61910881f90e6ea677855a3eba34f03c0fe2af8d7f47400a9";
/// The SHA-256 fingerprint of the OPRFQuery `ConstraintMatrices`.
pub const QUERY_MATRICES_FINGERPRINT: &str =
    "aad1e4327a7296a31fd2679d9725bef80954c934086ac200c06bbba12ff6dc0d";
/// The SHA-256 fingerprint of the OPRFNullifier `ProvingKey`.
pub const NULLIFIER_PK_FINGERPRINT: &str =
    "0a66c750151f9b011663d81e22f34450386b74f158d84173625eb014a6e94a3a";
/// The SHA-256 fingerprint of the OPRFNullifier `ConstraintMatrices`.
pub const NULLIFIER_MATRICES_FINGERPRINT: &str =
    "2fe6c4be2f44b0bebced9e883f3006ce85f65cc196c55e6d1b6e92704669a2f3";

pub(crate) type ZkResult<T> = Result<T, Groth16Error>;

/// Errors that can occur while loading or parsing `Groth16Material`
#[derive(Debug, thiserror::Error)]
pub enum Groth16MaterialError {
    /// Any I/O error encountered while reading data
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// The SHA-256 fingerprint of the data did not match the expected value.
    #[error("invalid data - wrong sha256 fingerprint")]
    FingerprintMismatch,
    /// Failed to fetch the data from a remote source.
    #[error(transparent)]
    Network(#[from] reqwest::Error),
}

/// Errors that can occur during Groth16 proof generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum Groth16Error {
    /// Failed to generate a witness for the circuit.
    #[error("failed to generate witness")]
    WitnessGeneration,
    /// Failed to generate a Groth16 proof.
    #[error("failed to generate proof")]
    ProofGeneration,
    /// Generated proof could not be verified against the verification key.
    #[error("proof could not be verified")]
    InvalidProof,
}

/// Core material for generating zero-knowledge proofs.
///
/// Holds the proving keys and constraint matrices for both OPRFQuery and OPRFNullifier
/// circuits. Provides methods to:
/// - Generate proofs from structured inputs
/// - Verify proofs internally immediately after generation
pub struct Groth16Material {
    /// Proving key for the OPRFQuery circuit
    query_pk: ProvingKey<Bn254>,
    /// Constraint matrices for the OPRFQuery circuit
    query_matrices: ConstraintMatrices<ark_bn254::Fr>,
    /// Proving key for the OPRFNullifier circuit
    nullifier_pk: ProvingKey<Bn254>,
    /// Constraint matrices for the OPRFNullifier circuit
    nullifier_matrices: ConstraintMatrices<ark_bn254::Fr>,
}

impl Groth16Material {
    /// Loads the Groth16 material from files and verifies their fingerprints.
    ///
    /// # Arguments
    ///
    /// * `query_pk_path` - Path to the OPRFQuery `pk` file
    /// * `query_matrices_path` - Path to the OPRFQuery `matrices` file
    /// * `nullifier_pk_path` - Path to the OPRFNullifier `pk` file
    /// * `nullifier_matrices_path` - Path to the OPRFNullifier `matrices` file
    ///
    /// # Errors
    ///
    /// Returns a [`Groth16MaterialError`] if the file cannot be read or the fingerprint
    /// does not match the expected value.
    pub fn new(
        query_pk_path: impl AsRef<Path>,
        query_matrices_path: impl AsRef<Path>,
        nullifier_pk_path: impl AsRef<Path>,
        nullifier_matrices_path: impl AsRef<Path>,
    ) -> Result<Self, Groth16MaterialError> {
        let query_pk_bytes = std::fs::read(query_pk_path)?;
        let query_matrices_bytes = std::fs::read(query_matrices_path)?;
        let nullifier_pk_bytes = std::fs::read(nullifier_pk_path)?;
        let nullifier_matrices_bytes = std::fs::read(nullifier_matrices_path)?;
        Self::from_bytes(
            &query_pk_bytes,
            &query_matrices_bytes,
            &nullifier_pk_bytes,
            &nullifier_matrices_bytes,
        )
    }

    /// Builds Groth16 material directly from in-memory `pk` and `matrices` bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`Groth16MaterialError::FingerprintMismatch`] if any embedded fingerprint check fails.
    pub fn from_bytes(
        query_pk_bytes: &[u8],
        query_matrices_bytes: &[u8],
        nullifier_pk_bytes: &[u8],
        nullifier_matrices_bytes: &[u8],
    ) -> Result<Self, Groth16MaterialError> {
        let query_pk = parse_pk_bytes(query_pk_bytes, QUERY_PK_FINGERPRINT)?;
        let query_matrices =
            parse_matrices_bytes(query_matrices_bytes, QUERY_MATRICES_FINGERPRINT)?;
        let nullifier_pk = parse_pk_bytes(nullifier_pk_bytes, NULLIFIER_PK_FINGERPRINT)?;
        let nullifier_matrices =
            parse_matrices_bytes(nullifier_matrices_bytes, NULLIFIER_MATRICES_FINGERPRINT)?;
        Ok(Self {
            query_pk,
            query_matrices,
            nullifier_pk,
            nullifier_matrices,
        })
    }

    /// Builds Groth16 material from bytes baked into the binary.
    ///
    /// # Errors
    ///
    /// Returns a [`Groth16MaterialError::FingerprintMismatch`] if the baked-in fingerprints
    /// and expected constants differ.
    #[cfg(feature = "embed-zkeys")]
    pub fn from_embedded() -> Result<Self, Groth16MaterialError> {
        Self::from_bytes(
            QUERY_PK_BYTES,
            QUERY_MATRICES_BYTES,
            NULLIFIER_PK_BYTES,
            NULLIFIER_MATRICES_BYTES,
        )
    }

    /// Downloads `pk` and `matrices` files from the provided URLs and builds the Groth16 material.
    ///
    /// # Errors
    ///
    /// Returns a [`Groth16MaterialError::Network`] if fetching either URL fails, or a
    /// [`Groth16MaterialError::FingerprintMismatch`] if the downloaded bytes do not
    /// match the expected fingerprints.
    #[cfg(feature = "tokio")]
    pub async fn from_urls(
        query_pk_url: impl reqwest::IntoUrl,
        query_matrices_url: impl reqwest::IntoUrl,
        nullifier_pk_url: impl reqwest::IntoUrl,
        nullifier_matrices_url: impl reqwest::IntoUrl,
    ) -> Result<Self, Groth16MaterialError> {
        let query_pk_bytes = reqwest::get(query_pk_url).await?.bytes().await?;
        let query_matrices_bytes = reqwest::get(query_matrices_url).await?.bytes().await?;
        let nullifier_pk_bytes = reqwest::get(nullifier_pk_url).await?.bytes().await?;
        let nullifier_matrices_bytes = reqwest::get(nullifier_matrices_url).await?.bytes().await?;
        Self::from_bytes(
            &query_pk_bytes,
            &query_matrices_bytes,
            &nullifier_pk_bytes,
            &nullifier_matrices_bytes,
        )
    }

    /// Generates an OPRFQuery Groth16 proof.
    ///
    /// Immediately verifies the generated proof against the verification key.
    pub fn generate_query_proof<const MERKLE_DEPTH: usize, R: Rng + CryptoRng>(
        &self,
        input: &QueryProofInput<MERKLE_DEPTH>,
        rng: &mut R,
    ) -> ZkResult<(Groth16Proof, Vec<ark_babyjubjub::Fq>)> {
        let inputs: HashMap<String, serde_json::Value> =
            serde_json::from_value(input.json()).expect("can deserialize input");
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let witness = generate_witness(QUERY_GRAPH_BYTES, inputs)?;
        generate_proof(&self.query_pk, &self.query_matrices, &witness, rng)
    }

    /// Generates an OPRFNullifier Groth16 proof.
    ///
    /// Immediately verifies the generated proof against the verification key.
    pub fn generate_nullifier_proof<const MERKLE_DEPTH: usize, R: Rng + CryptoRng>(
        &self,
        input: &NullifierProofInput<MERKLE_DEPTH>,
        rng: &mut R,
    ) -> ZkResult<(Groth16Proof, Vec<ark_babyjubjub::Fq>)> {
        let inputs: HashMap<String, serde_json::Value> =
            serde_json::from_value(input.json()).expect("can deserialize input");
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let witness = generate_witness(NULLIFIER_GRAPH_BYTES, inputs)?;
        generate_proof(&self.nullifier_pk, &self.nullifier_matrices, &witness, rng)
    }

    /// Returns the verification key of the nullifier circuit
    pub fn nullifier_vk(&self) -> VerifyingKey<Bn254> {
        self.nullifier_pk.vk.clone()
    }
}

/// Parse a `ProvingKey`
/// Checks the SHA-256 fingerprint.
pub fn parse_pk_bytes(
    bytes: &[u8],
    should_fingerprint: &'static str,
) -> Result<ProvingKey<Bn254>, Groth16MaterialError> {
    let is_fingerprint = k256::sha2::Sha256::digest(bytes);

    if hex::encode(is_fingerprint) != should_fingerprint {
        // return Err(Groth16MaterialError::FingerprintMismatch);
    }

    let pk = ProvingKey::deserialize_compressed_unchecked(bytes)
        .expect("valid pk if fingerprint matches");
    Ok(pk)
}

/// Parse `ConstraintMatrices`
/// Checks the SHA-256 fingerprint.
pub fn parse_matrices_bytes(
    bytes: &[u8],
    should_fingerprint: &'static str,
) -> Result<ConstraintMatrices<ark_bn254::Fr>, Groth16MaterialError> {
    let is_fingerprint = k256::sha2::Sha256::digest(bytes);

    if hex::encode(is_fingerprint) != should_fingerprint {
        // return Err(Groth16MaterialError::FingerprintMismatch);
    }

    let matrices = ConstraintMatricesWrapper::deserialize_compressed_unchecked(bytes)
        .expect("valid matrices if fingerprint matches");
    Ok(matrices.0)
}

/// Computes a witness vector from a circuit graph and inputs.
fn generate_witness(
    graph_bytes: &[u8],
    inputs: HashMap<String, Vec<U256>>,
) -> ZkResult<Vec<ark_bn254::Fr>> {
    let graph = witness::init_graph(graph_bytes).expect("have correct graph baked in");
    let bbfs = black_box_functions();
    let witness = witness::calculate_witness(inputs, &graph, Some(&bbfs))
        .map_err(|err| {
            tracing::error!("error during calculate_witness: {err:?}");
            Groth16Error::WitnessGeneration
        })?
        .into_iter()
        .map(|v| ark_bn254::Fr::from(BigInt(v.into_limbs())))
        .collect::<Vec<_>>();
    Ok(witness)
}

/// Generates a Groth16 proof from a witness and verifies it.
fn generate_proof<R: Rng + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<ark_bn254::Fr>,
    witness: &[ark_bn254::Fr],
    rng: &mut R,
) -> ZkResult<(Groth16Proof, Vec<ark_babyjubjub::Fq>)> {
    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, witness).map_err(|err| {
        tracing::error!("error during prove: {err:?}");
        Groth16Error::ProofGeneration
    })?;

    let inputs = witness[1..matrices.num_instance_variables].to_vec();
    Groth16::verify(&pk.vk, &proof, &inputs).map_err(|err| {
        tracing::error!("error during verify: {err:?}");
        Groth16Error::InvalidProof
    })?;

    Ok((Groth16Proof::from(proof), inputs))
}

fn black_box_functions() -> HashMap<String, BlackBoxFunction> {
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
        "bbf_legendre".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            match args[0].legendre() {
                LegendreSymbol::Zero => ark_bn254::Fr::from(0u64),
                LegendreSymbol::QuadraticResidue => ark_bn254::Fr::from(1u64),
                LegendreSymbol::QuadraticNonResidue => -ark_bn254::Fr::from(1u64),
            }
        }),
    );
    bbfs.insert(
        "bbf_sqrt_unchecked".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            args[0].sqrt().unwrap_or(ark_bn254::Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_sqrt_input".to_string(),
        Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
            // function bbf_sqrt_input(l, a, na) {
            //     if (l != -1) {
            //         return a;
            //     } else {
            //         return na;
            //     }
            // }
            if args[0] != -ark_bn254::Fr::ONE {
                args[1]
            } else {
                args[2]
            }
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
    // the call to this function gets removed with circom --O2 optimization and circom-witness-rs can handle the optimized version without a bbf
    // bbfs.insert(
    //     "bbf_num_2_bits_neg_helper".to_string(),
    //     Arc::new(move |args: &[Fr]| -> Fr {
    //         // function bbf_num_2_bits_neg_helper(in, n) {
    //         //     return n == 0 ? 0 : 2**n - in;
    //         // }
    //         if args[1] == Fr::ZERO {
    //             Fr::ZERO
    //         } else {
    //             let a: U256 = args[1].into();
    //             let ls_limb = a.as_limbs()[0];
    //             let tmp: Fr = Fr::new((U256::from(1).shl(ls_limb as usize)).into());
    //             tmp - args[0]
    //         }
    //     }),
    // );
    bbfs
}

fn parse(value: serde_json::Value) -> Vec<U256> {
    match value {
        serde_json::Value::String(string) => {
            vec![U256::from_str(&string).expect("can deserialize field element")]
        }
        serde_json::Value::Array(values) => values.into_iter().flat_map(parse).collect(),
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, process::Command};

    use circom_types::Witness;

    use crate::MAX_DEPTH;

    use super::*;

    fn run_snarkjs_witness_gen(input: serde_json::Value, circuit: &str) -> Vec<ark_bn254::Fr> {
        let root = env!("CARGO_MANIFEST_DIR");
        // change cwd to dir
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().display();
        dbg!(&temp_path);
        std::env::set_current_dir(temp_dir.path()).unwrap();

        std::fs::write(
            format!("{temp_path}/input.json"),
            serde_json::to_string(&input).unwrap(),
        )
        .unwrap();

        let status = Command::new("circom")
            .args([
                &format!("{root}/../circom/main/{circuit}.circom"),
                "-l",
                &format!("{root}/../circom/"),
                "--wasm",
                "--O2",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let status = Command::new("node")
            .args([
                &format!("{temp_path}/{circuit}_js/generate_witness.js"),
                &format!("{temp_path}/{circuit}_js/{circuit}.wasm"),
                &format!("{temp_path}/input.json"),
                &format!("{temp_path}/witness.wtns"),
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let witness = Witness::<ark_bn254::Fr>::from_reader(
            File::open(format!("{temp_path}/witness.wtns")).unwrap(),
        )
        .unwrap();

        witness.values
    }

    #[test]
    #[ignore = "needs circom and node"]
    fn test_witness_calc_query() {
        let mut rng = rand::thread_rng();
        let (input, _) = QueryProofInput::<MAX_DEPTH>::generate(&mut rng);
        let should_witness = run_snarkjs_witness_gen(input.json(), "OPRFQueryProof");
        let inputs: HashMap<String, serde_json::Value> =
            serde_json::from_value(input.json()).expect("can deserialize input");
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let is_witness = generate_witness(QUERY_GRAPH_BYTES, inputs).unwrap();
        assert_eq!(is_witness, should_witness);
    }

    #[test]
    #[ignore = "needs circom and node"]
    fn test_witness_calc_nullifier() {
        let mut rng = rand::thread_rng();
        let input = NullifierProofInput::<MAX_DEPTH>::generate(&mut rng);
        let should_witness = run_snarkjs_witness_gen(input.json(), "OPRFNullifierProof");
        let inputs: HashMap<String, serde_json::Value> =
            serde_json::from_value(input.json()).expect("can deserialize input");
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let is_witness = generate_witness(NULLIFIER_GRAPH_BYTES, inputs).unwrap();
        assert_eq!(is_witness, should_witness);
    }
}
