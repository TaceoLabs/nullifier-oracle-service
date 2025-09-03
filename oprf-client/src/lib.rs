use std::{fs::File, path::PathBuf, process::Command, str::FromStr};

use eddsa_babyjubjub::EdDSAPrivateKey;
use oprf_core::{
    ddlog_equality::DLogEqualityChallenge,
    oprf::BlindedOPrfResponse,
    proof_input_gen::{nullifier::NullifierProofInput, query::QueryProofInput},
};
use oprf_service::{
    groth16::Groth16Proof,
    services::oprf::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse},
};
use rand::{CryptoRng, Rng};
use serde::Serialize;
use uuid::Uuid;

pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

pub mod config;

pub type ScalarField = ark_babyjubjub::Fr;
pub type BaseField = ark_babyjubjub::Fq;
pub type Affine = ark_babyjubjub::EdwardsAffine;
pub type Projective = ark_babyjubjub::EdwardsProjective;

#[derive(Debug, thiserror::Error)]
pub enum OprfError {}

pub async fn oprf<const MAX_DEPTH: usize, R: Rng + CryptoRng>(
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
    rng: &mut R,
) -> Result<(), OprfError> {
    let request_id = Uuid::new_v4();
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
    let (proof, public) = generate_query_proof(&query_input);

    let req = OprfRequest {
        request_id,
        proof,
        public,
    };
    assert_eq!(query_input.q, req.public[..2]);

    let responses = oprf_request(oprf_services, &req).await;
    let commitments = responses
        .into_iter()
        .map(|res| res.commitments)
        .collect::<Vec<_>>();

    let blinded_query = Affine::new(query_input.q[0], query_input.q[1]);
    let (c, challenge) = DLogEqualityChallenge::combine_commitments_and_create_challenge(
        &commitments,
        oprf_public_key,
        blinded_query,
    );

    let req = ChallengeRequest {
        request_id,
        challenge: challenge.clone(),
    };
    let responses = challenge_request(oprf_services, &req).await;

    let dlog_proof_shares = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();

    // Combines all proofs
    let dlog_proof = challenge.combine_proofs(&dlog_proof_shares);

    // Nullifier inputs
    let blinded_response = BlindedOPrfResponse {
        request_id,
        blinded_response: c,
    };

    let nullifier_input = NullifierProofInput::new(
        oprf_public_key,
        signal_hash,
        query_input,
        query,
        blinded_response,
        dlog_proof,
    );
    let (proof, public) = generate_nullifier_proof(&nullifier_input);
    assert_eq!(nullifier_input.nullifier, public[0]);

    Ok(())
}

async fn oprf_request(oprf_services: &[String], req: &OprfRequest) -> Vec<OprfResponse> {
    let client = reqwest::Client::new();
    let mut responses = Vec::with_capacity(oprf_services.len());
    for url in oprf_services {
        let res = client
            .post(format!("{url}/api/v1/oprf/init"))
            .json(req)
            .send()
            .await
            .unwrap()
            .json::<OprfResponse>()
            .await
            .unwrap();
        responses.push(res);
    }
    assert!(responses.iter().all(|res| res.request_id == req.request_id));
    responses
}

async fn challenge_request(
    oprf_services: &[String],
    req: &ChallengeRequest,
) -> Vec<ChallengeResponse> {
    let client = reqwest::Client::new();
    let mut responses = Vec::with_capacity(oprf_services.len());
    for url in oprf_services {
        let res = client
            .post(format!("{url}/api/v1/oprf/finish"))
            .json(req)
            .send()
            .await
            .unwrap()
            .json::<ChallengeResponse>()
            .await
            .unwrap();
        responses.push(res);
    }
    assert!(responses.iter().all(|res| res.request_id == req.request_id));
    responses
}

fn generate_proof<T: Serialize>(
    input: T,
    dir: PathBuf,
    circuit_name: &str,
) -> (Groth16Proof, Vec<ark_babyjubjub::Fq>) {
    std::fs::write(
        "/tmp/input.json",
        serde_json::to_string_pretty(&input).unwrap(),
    )
    .unwrap();

    let status = Command::new("node")
        .args([
            dir.join(format!("{circuit_name}_js/generate_witness.js"))
                .to_str()
                .unwrap(),
            dir.join(format!("{circuit_name}_js/{circuit_name}.wasm"))
                .to_str()
                .unwrap(),
            "/tmp/input.json",
            "/tmp/witness.wtns",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("snarkjs")
        .args([
            "groth16",
            "prove",
            dir.join(format!("{circuit_name}.zkey")).to_str().unwrap(),
            "/tmp/witness.wtns",
            "/tmp/proof.json",
            "/tmp/public.json",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("snarkjs")
        .args([
            "groth16",
            "verify",
            dir.join(format!("{circuit_name}.vk.json"))
                .to_str()
                .unwrap(),
            "/tmp/public.json",
            "/tmp/proof.json",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let proof =
        serde_json::from_reader::<_, Groth16Proof>(File::open("/tmp/proof.json").unwrap()).unwrap();

    let public =
        serde_json::from_reader::<_, Vec<String>>(File::open("/tmp/public.json").unwrap()).unwrap();
    let public = public
        .iter()
        .map(|x| ark_babyjubjub::Fq::from_str(x).unwrap())
        .collect();

    (proof, public)
}

fn generate_query_proof<const MAX_DEPTH: usize>(
    input: &QueryProofInput<MAX_DEPTH>,
) -> (Groth16Proof, Vec<ark_babyjubjub::Fq>) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom/main");
    generate_proof(input.json(), dir, "OPRFQueryProof")
}

fn generate_nullifier_proof<const MAX_DEPTH: usize>(
    input: &NullifierProofInput<MAX_DEPTH>,
) -> (Groth16Proof, Vec<ark_babyjubjub::Fq>) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom/main");
    generate_proof(input.json(), dir, "OPRFNullifierProof")
}
