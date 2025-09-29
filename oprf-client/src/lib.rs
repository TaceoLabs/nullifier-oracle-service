use oprf_core::oprf::{BlindedOPrfRequest, OprfClient};
use std::ops::Shr;
use std::time::Instant;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup as _, BigInt, Field as _, LegendreSymbol, UniformRand as _};
use ark_serde_compat::groth16::Groth16Proof;
use groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey};
use oprf_core::shamir;
use oprf_core::{
    ddlog_equality::DLogEqualityChallenge,
    proof_input_gen::{nullifier::NullifierProofInput, query::QueryProofInput},
};
use oprf_types::api::v1::{ChallengeRequest, NullifierShareIdentifier, OprfRequest};
use oprf_types::crypto::UserPublicKeyBatch;
use oprf_types::{MerkleEpoch, MerkleRoot, RpId, ShareEpoch};
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use witness::{BlackBoxFunction, ruint::aliases::U256};

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

pub mod config;

pub mod tokio;

pub const MAX_DEPTH: usize = 30;

const QUERY_BYTES: &[u8] = include_bytes!("../../query_graph.bin");
const NULLIFIER_BYTES: &[u8] = include_bytes!("../../nullifier_graph.bin");

pub type ScalarField = ark_babyjubjub::Fr;
pub type BaseField = ark_babyjubjub::Fq;
pub type Affine = ark_babyjubjub::EdwardsAffine;
pub type Projective = ark_babyjubjub::EdwardsProjective;

pub struct CredentialsSignature {
    // Credential Signature
    pub type_id: BaseField,
    pub issuer: EdDSAPublicKey,
    pub hashes: [BaseField; 2], // [claims_hash, associated_data_hash]
    pub signature: EdDSASignature,
    pub genesis_issued_at: u64,
    pub expires_at: u64,
}

pub struct MerkleMembership {
    pub epoch: MerkleEpoch,
    pub root: MerkleRoot,
    pub depth: u64,
    pub mt_index: u64,
    pub siblings: Vec<BaseField>,
}

pub struct OprfQuery {
    pub rp_id: RpId,
    pub share_epoch: ShareEpoch,
    pub action: BaseField,
    pub nonce: BaseField,
    pub current_time_stamp: u64,
}

pub struct UserSignature {
    // Signature
    pub pk_batch: UserPublicKeyBatch,
    pub pk_index: u64, // 0..6
    pub signature: EdDSASignature,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ApiError(#[from] reqwest::Error),
    #[error("expected degree {threshold} responses, got {n}")]
    NotEnoughOprfResponses { n: usize, threshold: usize },
    #[error("failed to generate witness")]
    WitnessGeneration,
    #[error("failed to generate proof")]
    ProofGeneration,
    #[error("prove could not be verified")]
    InvalidProof,
    #[error("invalid merkle length, expected {expected}, but is {is}")]
    InvalidSiblingsLength { expected: usize, is: usize },
    #[error("invalid circuit graph")]
    InvalidCircuitGraph,
    #[error("DLog prove could not be verified")]
    InvalidDLogProof,
    #[error("Index in public-key batch must be in range [0..6], but is {0}")]
    InvalidPublicKeyIndex(u64),
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

pub struct OprfSession {
    request_id: Uuid,
    credentials_signature: CredentialsSignature,
    merkle_membership: MerkleMembership,
}

pub struct OprfSessionSignedQuery {
    query_hash: BaseField,
    request_id: Uuid,
    merkle_depth: u64,
    merkle_epoch: MerkleEpoch,
    query: OprfQuery,
    credential_issuer: EdDSAPublicKey,
    blinded_request: BlindedOPrfRequest,
    query_input: QueryProofInput<MAX_DEPTH>,
}

pub struct OprfSessionCreatedRequest {
    request_id: Uuid,
    oprf_request: OprfRequest,
    query: OprfQuery,
    blinded_request: BlindedOPrfRequest,
    query_proof_input: QueryProofInput<MAX_DEPTH>,
    query_hash: BaseField,
}

pub struct OprfSessionInitSessions {
    request_id: Uuid,
    challenge_request: ChallengeRequest,
    services: Vec<String>,
    lagrange: Vec<ScalarField>,
    blinded_request: BlindedOPrfRequest,
    blinded_response: Affine,
    query_proof_input: QueryProofInput<MAX_DEPTH>,
    query_hash: BaseField,
    rp_nullifier_key: Affine,
}

impl OprfSessionCreatedRequest {
    pub async fn init_sessions(
        self,
        oprf_services: &[String],
        threshold: usize,
        rp_nullifier_key: Affine,
    ) -> Result<OprfSessionInitSessions> {
        let (services, sessions) =
            tokio::init_sessions(oprf_services, threshold, self.oprf_request).await?;

        let (party_ids, commitments) = sessions
            .into_iter()
            .map(|session| {
                (
                    usize::from(session.party_id.into_inner() + 1),
                    session.commitments,
                )
            })
            .collect::<(Vec<_>, Vec<_>)>();

        let lagrange = shamir::lagrange_from_coeff(&party_ids);
        let (blinded_response, challenge) =
            DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
                &commitments,
                &lagrange,
                rp_nullifier_key,
                self.blinded_request.blinded_query(),
            );
        Ok(OprfSessionInitSessions {
            query_proof_input: self.query_proof_input,
            query_hash: self.query_hash,
            request_id: self.request_id,
            lagrange,
            services,
            blinded_request: self.blinded_request,
            blinded_response,
            rp_nullifier_key,
            challenge_request: ChallengeRequest {
                request_id: self.request_id,
                challenge,
                rp_identifier: NullifierShareIdentifier {
                    rp_id: self.query.rp_id,
                    share_epoch: self.query.share_epoch,
                },
            },
        })
    }
}

impl OprfSessionInitSessions {
    pub async fn challenge<R: Rng + CryptoRng>(
        self,
        signal_hash: BaseField,
        id_commitment_r: BaseField,
        pk: &ProvingKey<Bn254>,
        matrices: &ConstraintMatrices<ark_bn254::Fr>,
        rng: &mut R,
    ) -> Result<(Groth16Proof, Vec<BaseField>, BaseField)> {
        let challenge = self.challenge_request.challenge.clone();
        let responses = tokio::finish_sessions(&self.services, self.challenge_request).await?;
        let proofs = responses
            .into_iter()
            .map(|res| res.proof_share)
            .collect::<Vec<_>>();
        let dlog_proof = challenge.combine_proofs_shamir(&proofs, &self.lagrange);
        tracing::info!("checking second proof");
        if !dlog_proof.verify(
            self.rp_nullifier_key,
            self.blinded_request.blinded_query(),
            self.blinded_response,
            Affine::generator(),
        ) {
            return Err(Error::InvalidDLogProof);
        }

        let nullifier_input = NullifierProofInput::new(
            self.request_id,
            self.rp_nullifier_key,
            signal_hash,
            self.query_proof_input,
            self.query_hash,
            self.blinded_response,
            dlog_proof,
            id_commitment_r,
        );
        let (proof, public) = generate_nullifier_proof(&nullifier_input, pk, matrices, rng)?;
        Ok((proof, public, nullifier_input.nullifier))
    }
}

impl OprfSessionSignedQuery {
    pub fn create_oprf_request<R: Rng + CryptoRng>(
        self,
        pk: &ProvingKey<Bn254>,
        matrices: &ConstraintMatrices<ark_bn254::Fr>,
        nonce_signature: k256::ecdsa::Signature,
        rng: &mut R,
    ) -> Result<OprfSessionCreatedRequest> {
        let inputs: HashMap<String, serde_json::Value> =
            serde_json::from_value(self.query_input.json()).expect("can deserialize input");
        let inputs = inputs
            .into_iter()
            .map(|(name, value)| (name, parse(value)))
            .collect();
        let witness = generate_witness(QUERY_BYTES, inputs)?;
        let (proof, _) = generate_proof(pk, matrices, &witness, rng)?;
        Ok(OprfSessionCreatedRequest {
            request_id: self.request_id,
            query_hash: self.query_hash,
            query_proof_input: self.query_input,
            oprf_request: OprfRequest {
                request_id: self.request_id,
                proof,
                point_b: self.blinded_request.blinded_query(),
                rp_identifier: NullifierShareIdentifier {
                    rp_id: self.query.rp_id,
                    share_epoch: self.query.share_epoch,
                },
                merkle_epoch: self.merkle_epoch,
                action: self.query.action,
                nonce: self.query.nonce,
                signature: nonce_signature,
                cred_pk: self.credential_issuer.clone(),
                current_time_stamp: self.query.current_time_stamp,
                merkle_depth: self.merkle_depth,
            },
            blinded_request: self.blinded_request,
            query: self.query,
        })
    }
}

impl OprfSession {
    pub fn init(
        credentials_signature: CredentialsSignature,
        merkle_membership: MerkleMembership,
    ) -> Result<Self> {
        if merkle_membership.siblings.len() == MAX_DEPTH {
            Ok(Self {
                request_id: Uuid::new_v4(),
                credentials_signature,
                merkle_membership,
            })
        } else {
            Err(Error::InvalidSiblingsLength {
                expected: MAX_DEPTH,
                is: merkle_membership.siblings.len(),
            })
        }
    }

    pub fn sign_oprf_query<R: Rng + CryptoRng>(
        self,
        query: OprfQuery,
        pk_batch: UserPublicKeyBatch,
        pk_index: u64,
        sk: EdDSAPrivateKey,
        rng: &mut R,
    ) -> Result<OprfSessionSignedQuery> {
        if pk_index > 7 {
            return Err(Error::InvalidPublicKeyIndex(pk_index));
        }
        let query_hash = OprfClient::generate_query(
            self.merkle_membership.mt_index.into(),
            query.rp_id.into_inner().into(),
            query.action,
        );
        let oprf_client = OprfClient::new(sk.public().pk);
        let (blinded_request, blinding_factor) =
            oprf_client.blind_query(self.request_id, query_hash, rng);
        let signature = sk.sign(blinding_factor.query());

        let query_input = QueryProofInput::<MAX_DEPTH> {
            pk: pk_batch.into_proof_input(),
            pk_index: pk_index.into(),
            s: signature.s,
            r: [signature.r.x, signature.r.y],
            cred_type_id: self.credentials_signature.type_id,
            cred_pk: [
                self.credentials_signature.issuer.pk.x,
                self.credentials_signature.issuer.pk.y,
            ],
            cred_hashes: self.credentials_signature.hashes,
            cred_genesis_issued_at: self.credentials_signature.genesis_issued_at.into(),
            cred_expires_at: self.credentials_signature.expires_at.into(),
            cred_s: self.credentials_signature.signature.s,
            cred_r: [
                self.credentials_signature.signature.r.x,
                self.credentials_signature.signature.r.y,
            ],
            current_time_stamp: query.current_time_stamp.into(),
            merkle_root: self.merkle_membership.root.into_inner(),
            depth: self.merkle_membership.depth.into(),
            mt_index: self.merkle_membership.mt_index.into(),
            siblings: self
                .merkle_membership
                .siblings
                .try_into()
                .expect("checked in init step"),
            beta: blinding_factor.beta(),
            rp_id: query.rp_id.into_inner().into(),
            action: query.action,
            nonce: query.nonce,
            q: blinded_request.blinded_query_as_public_output(),
        };

        Ok(OprfSessionSignedQuery {
            merkle_depth: self.merkle_membership.depth,
            query_hash,
            query,
            merkle_epoch: self.merkle_membership.epoch,
            request_id: self.request_id,
            blinded_request,
            credential_issuer: self.credentials_signature.issuer,
            query_input,
        })
    }
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

fn generate_nullifier_proof<const MERLE_DEPTH: usize, R: Rng + CryptoRng>(
    input: &NullifierProofInput<MERLE_DEPTH>,
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<ark_bn254::Fr>,
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<BaseField>)> {
    let inputs: HashMap<String, serde_json::Value> =
        serde_json::from_value(input.json()).expect("can deserialize input");
    let inputs = inputs
        .into_iter()
        .map(|(name, value)| (name, parse(value)))
        .collect();
    let witness = generate_witness(NULLIFIER_BYTES, inputs)?;
    generate_proof(pk, matrices, &witness, rng)
}

fn generate_witness(
    graph_bytes: &[u8],
    inputs: HashMap<String, Vec<U256>>,
) -> Result<Vec<ark_bn254::Fr>> {
    let graph = witness::init_graph(graph_bytes).map_err(|err| {
        tracing::error!("error during init_graph: {err:?}");
        Error::InvalidCircuitGraph
    })?;
    let bbfs = black_box_functions();
    let start = Instant::now();
    let witness = witness::calculate_witness(inputs, &graph, Some(&bbfs))
        .map_err(|err| {
            tracing::error!("error during calculate_witness: {err:?}");
            Error::WitnessGeneration
        })?
        .into_iter()
        .map(|v| ark_bn254::Fr::from(BigInt(v.into_limbs())))
        .collect::<Vec<_>>();
    tracing::debug!("witness extension took {}ms", start.elapsed().as_millis());
    Ok(witness)
}

fn generate_proof<R: Rng + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<ark_bn254::Fr>,
    witness: &[ark_bn254::Fr],
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<BaseField>)> {
    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let start = Instant::now();
    let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, witness).map_err(|err| {
        tracing::error!("error during prove: {err:?}");
        Error::ProofGeneration
    })?;
    tracing::debug!("prove took {}ms", start.elapsed().as_millis());

    let inputs = witness[1..matrices.num_instance_variables].to_vec();
    Groth16::verify(&pk.vk, &proof, &inputs).map_err(|err| {
        tracing::error!("error during verify: {err:?}");
        Error::InvalidProof
    })?;

    Ok((Groth16Proof::from(proof), inputs))
}

fn black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();
    bbfs.insert(
        "bbf_inv".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            // function bb_finv(in) {
            //     return in!=0 ? 1/in : 0;
            // }
            args[0].inverse().unwrap_or(Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_legendre".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            match args[0].legendre() {
                LegendreSymbol::Zero => Fr::from(0u64),
                LegendreSymbol::QuadraticResidue => Fr::from(1u64),
                LegendreSymbol::QuadraticNonResidue => -Fr::from(1u64),
            }
        }),
    );
    bbfs.insert(
        "bbf_sqrt_unchecked".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr { args[0].sqrt().unwrap_or(Fr::ZERO) }),
    );
    bbfs.insert(
        "bbf_sqrt_input".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            // function bbf_sqrt_input(l, a, na) {
            //     if (l != -1) {
            //         return a;
            //     } else {
            //         return na;
            //     }
            // }
            if args[0] != -Fr::ONE {
                args[1]
            } else {
                args[2]
            }
        }),
    );
    bbfs.insert(
        "bbf_num_2_bits_helper".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            // function bbf_num_2_bits_helper(in, i) {
            //     return (in >> i) & 1;
            // }
            let a: U256 = args[0].into();
            let b: U256 = args[1].into();
            let ls_limb = b.as_limbs()[0];
            Fr::new((a.shr(ls_limb as usize) & U256::from(1)).into())
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

#[cfg(test)]
mod tests {
    use std::{fs::File, process::Command};

    use circom_types::Witness;

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
        let is_witness = generate_witness(QUERY_BYTES, inputs).unwrap();
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
        let is_witness = generate_witness(NULLIFIER_BYTES, inputs).unwrap();
        assert_eq!(is_witness, should_witness);
    }
}
