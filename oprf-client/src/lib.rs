use std::ops::{Shl, Shr};
use std::time::Instant;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use ark_bn254::{Bn254, Fr};
use ark_ff::{
    AdditiveGroup as _, BigInt, Field as _, LegendreSymbol, PrimeField, UniformRand as _,
};
use eddsa_babyjubjub::EdDSAPrivateKey;
use groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey};
use oprf_core::shamir;
use oprf_core::{
    ark_serde_compat::groth16::Groth16Proof,
    ddlog_equality::DLogEqualityChallenge,
    proof_input_gen::{nullifier::NullifierProofInput, query::QueryProofInput},
};
use oprf_service::services::oprf::{
    ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse,
};
use rand::seq::IteratorRandom as _;
use rand::{CryptoRng, Rng};
use tracing::instrument;
use uuid::Uuid;

pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;
use witness::{BlackBoxFunction, ruint::aliases::U256};

pub mod config;

pub const MAX_DEPTH: usize = 30;

const QUERY_BYTES: &[u8] = include_bytes!("../../query_graph.bin");
const NULLIFIER_BYTES: &[u8] = include_bytes!("../../nullifier_graph.bin");

pub type ScalarField = ark_babyjubjub::Fr;
pub type BaseField = ark_babyjubjub::Fq;
pub type Affine = ark_babyjubjub::EdwardsAffine;
pub type Projective = ark_babyjubjub::EdwardsProjective;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ApiError(#[from] reqwest::Error),
    #[error("expected {degree} + 1 oprf responses, got {n}")]
    NotEnoughOprfResponses { n: usize, degree: usize },
    #[error("failed to generate witness")]
    WitnessGeneration,
    #[error("failed to generate proof")]
    ProofGeneration,
    #[error("prove could not be verified")]
    InvalidProof,
    #[error("invalid circuit graph")]
    InvalidCircuitGraph,
}

#[instrument(level = "debug", skip_all)]
#[expect(clippy::too_many_arguments)]
pub async fn nullifier<R: Rng + CryptoRng>(
    oprf_services: &[String],
    oprf_public_key: Affine,
    sk: EdDSAPrivateKey,
    pks: [[BaseField; 2]; MAX_PUBLIC_KEYS],
    pk_index: u64,
    merkle_root: BaseField,
    mt_index: u64,
    siblings: [BaseField; MAX_DEPTH],
    rp_id: BaseField,
    action: BaseField,
    signal_hash: BaseField,
    degree: usize,
    query_pk: &ProvingKey<Bn254>,
    query_matrices: &ConstraintMatrices<ark_bn254::Fr>,
    nullifier_pk: &ProvingKey<Bn254>,
    nullifier_matrices: &ConstraintMatrices<ark_bn254::Fr>,
    rng: &mut R,
) -> Result<(Groth16Proof, BaseField)> {
    let request_id = Uuid::new_v4();
    tracing::debug!("new request with id = {request_id}");

    tracing::debug!("generate query witness and proof");
    let (query_input, query) = QueryProofInput::new(
        request_id,
        sk,
        pks,
        pk_index,
        merkle_root,
        mt_index,
        siblings,
        rp_id,
        action,
        rng,
    );
    let blinded_query = Affine::new(query_input.q[0], query_input.q[1]);
    let (proof, public) = generate_query_proof(&query_input, query_pk, query_matrices, rng)?;
    assert_eq!(
        blinded_query,
        Affine::new(public[0], public[1]),
        "blinded query does not match"
    );

    tracing::debug!("request commitments");
    let req = OprfRequest {
        request_id,
        proof,
        public,
    };
    let responses = oprf_request(oprf_services, &req).await;
    let (parties, responses) = choose_party_responses(responses, degree, rng)?;
    let lagrange = shamir::lagrange_from_coeff(&parties);
    let commitments = responses
        .into_iter()
        .map(|res| res.commitments)
        .collect::<Vec<_>>();

    tracing::debug!("combine commitments and create challenge");
    let (blinded_response, challenge) =
        DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
            &commitments,
            &lagrange,
            oprf_public_key,
            blinded_query,
        );

    tracing::debug!("request proof shares");
    let req = ChallengeRequest {
        request_id,
        challenge: challenge.clone(),
    };
    let selected_oprf_services = parties
        .iter()
        .map(|id| oprf_services[id - 1].clone())
        .collect::<Vec<String>>();
    let responses = challenge_request(&selected_oprf_services, &req).await?;
    let dlog_proof_shares = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();

    tracing::debug!("combine proof shares");
    let dlog_proof = challenge.combine_proofs_shamir(&dlog_proof_shares, &lagrange);

    let nullifier_input = NullifierProofInput::new(
        request_id,
        oprf_public_key,
        signal_hash,
        query_input,
        query,
        blinded_response,
        dlog_proof,
    );

    tracing::debug!("generate nullifier witness and proof");
    let (proof, public) =
        generate_nullifier_proof(&nullifier_input, nullifier_pk, nullifier_matrices, rng)?;
    assert_eq!(
        nullifier_input.nullifier, public[0],
        "nullifier does not match"
    );

    Ok((proof, nullifier_input.nullifier))
}

async fn oprf_request(oprf_services: &[String], req: &OprfRequest) -> Vec<(usize, OprfResponse)> {
    // TODO maybe create client in caller and reuse for both requests
    let client = reqwest::Client::new();
    // TODO FuturesOrdered
    let mut responses = Vec::with_capacity(oprf_services.len());
    for (id, url) in oprf_services.iter().enumerate() {
        let res = client
            .post(format!("{url}/api/v1/oprf/init"))
            .json(req)
            .send()
            .await;
        match res {
            Ok(res) => match res.json::<OprfResponse>().await {
                Ok(res) => {
                    if res.request_id == req.request_id {
                        responses.push((id, res));
                    } else {
                        tracing::warn!(
                            "service return response for invalid request_id {}",
                            res.request_id
                        );
                    }
                }
                Err(err) => tracing::warn!("failed to decode response to json error: {err:?}"),
            },
            Err(err) => tracing::debug!("request returned error: {err:?}"),
        }
    }
    responses
}

async fn challenge_request(
    oprf_services: &[String],
    req: &ChallengeRequest,
) -> Result<Vec<ChallengeResponse>> {
    // TODO maybe create client in caller and reuse for both requests
    let client = reqwest::Client::new();
    // TODO FuturesOrdered
    let mut responses = Vec::with_capacity(oprf_services.len());
    for url in oprf_services {
        let res = client
            .post(format!("{url}/api/v1/oprf/finish"))
            .json(req)
            .send()
            .await?
            .json::<ChallengeResponse>()
            .await?;
        responses.push(res);
    }
    debug_assert!(responses.iter().all(|res| res.request_id == req.request_id));
    Ok(responses)
}

fn choose_party_responses<R: Rng + CryptoRng>(
    responses: Vec<(usize, OprfResponse)>,
    degree: usize,
    rng: &mut R,
) -> Result<(Vec<usize>, Vec<OprfResponse>)> {
    let chosen_responses = responses.into_iter().choose_multiple(rng, degree + 1);
    let num_responses = chosen_responses.len();
    if num_responses != degree + 1 {
        return Err(Error::NotEnoughOprfResponses {
            n: num_responses,
            degree,
        });
    }
    let parties = chosen_responses
        .iter()
        .map(|(id, _)| id + 1)
        .collect::<Vec<usize>>();
    let chosen_responses = chosen_responses
        .into_iter()
        .map(|(_, res)| res)
        .collect::<Vec<OprfResponse>>();
    tracing::debug!("randomly selected parties: {parties:?}");
    Ok((parties, chosen_responses))
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

fn generate_query_proof<R: Rng + CryptoRng>(
    input: &QueryProofInput<MAX_DEPTH>,
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

    let graph = witness::init_graph(QUERY_BYTES).map_err(|err| {
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

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let start = Instant::now();
    let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, &witness).map_err(|err| {
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

fn generate_nullifier_proof<R: Rng + CryptoRng>(
    input: &NullifierProofInput<MAX_DEPTH>,
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

    let graph = witness::init_graph(NULLIFIER_BYTES).map_err(|err| {
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

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let start = Instant::now();
    let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, &witness).map_err(|err| {
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
            let a: U256 = U256::from_limbs(args[0].into_bigint().0);
            let b: U256 = U256::from_limbs(args[1].into_bigint().0);
            let ls_limb = b.as_limbs()[0];
            Fr::from(BigInt(
                (a.shr(ls_limb as usize) & U256::from(1)).into_limbs(),
            ))
        }),
    );
    bbfs.insert(
        "bbf_num_2_bits_neg_helper0".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            // function bbf_num_2_bits_neg_helper0(in, n) {
            //     return n == 0 ? 0 : 2**n - in;
            // }
            if args[1] == Fr::ZERO {
                Fr::ZERO
            } else {
                let a: U256 = U256::from_limbs(args[1].into_bigint().0);
                let ls_limb = a.as_limbs()[0];
                let tmp: Fr = Fr::from(BigInt((U256::from(1).shl(ls_limb as usize)).into_limbs()));
                tmp - args[0]
            }
        }),
    );
    bbfs.insert(
        "bbf_num_2_bits_neg_helper1".to_string(),
        Arc::new(move |args: &[Fr]| -> Fr {
            // function bbf_num_2_bits_neg_helper1(neg, i) {
            //     return (neg >> i) & 1;
            // }
            let a: U256 = U256::from_limbs(args[0].into_bigint().0);
            let b: U256 = U256::from_limbs(args[1].into_bigint().0);
            let ls_limb = b.as_limbs()[0];
            Fr::from(BigInt(
                (a.shr(ls_limb as usize) & U256::from(1)).into_limbs(),
            ))
        }),
    );
    bbfs
}
