use std::{slice::from_ref, vec};

use ark_babyjubjub::{EdwardsAffine, EdwardsProjective};
use ark_bn254::Bn254;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof};
use ark_serialize::CanonicalDeserialize;
use circom_types::groth16::JsonPublicInput;
use criterion::*;
use oprf_core::{
    ddlog_equality::{
        additive::{DLogCommitmentsAdditive, DLogSessionAdditive},
        shamir::{DLogCommitmentsShamir, DLogSessionShamir},
    },
    oprf::{
        self,
        server::{OprfKey, OprfServer},
    },
    shamir,
};
use oprf_zk::groth16_serde::Groth16Proof;
use rand::seq::IteratorRandom;
use uuid::Uuid;

const VK_BYTES: &[u8] = include_bytes!("vk.bin");
const PROOF_JSON: &str = include_str!("proof.json");
const PUBLIC_JSON: &str = include_str!("public.json");

fn groth16_proof() -> Groth16Proof {
    serde_json::from_str(PROOF_JSON).expect("works")
}

fn groth16_public() -> Vec<ark_bn254::Fr> {
    serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(PUBLIC_JSON)
        .expect("works")
        .values
}

fn vk() -> ark_groth16::PreparedVerifyingKey<Bn254> {
    ark_groth16::PreparedVerifyingKey::<Bn254>::deserialize_compressed(VK_BYTES).expect("works")
}

fn oprf_bench(c: &mut Criterion) {
    c.bench_function("OPRF Client Query", |b| {
        let rng = &mut rand::thread_rng();
        let query = ark_babyjubjub::Fq::rand(rng);

        b.iter(|| oprf::client::blind_query(query, rng));
    });

    c.bench_function("OPRF Client Proof Verify", |b| {
        let proof = Proof::<Bn254>::from(groth16_proof());
        let public = groth16_public();
        let vk = vk();

        b.iter(|| std::hint::black_box(Groth16::<Bn254>::verify_proof(&vk, &proof, &public)));
    });

    c.bench_function("OPRF/Server/Response", |b| {
        let rng = &mut rand::thread_rng();
        let key = OprfKey::random(rng);
        let server = OprfServer::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = oprf::client::blind_query(q, rng);
                query
            },
            |query| server.answer_query(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Server/ResponseWithProof", |b| {
        let rng = &mut rand::thread_rng();
        let key = OprfKey::random(rng);
        let server = OprfServer::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = oprf::client::blind_query(q, rng);
                query
            },
            |query| server.answer_query_with_proof(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Client/Finalize", |b| {
        let rng = &mut rand::thread_rng();
        let key = OprfKey::random(rng);
        let server = OprfServer::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = oprf::client::blind_query(q, rng);
                let blinding = blinding.prepare();
                let response = server.answer_query(query);
                (response, blinding)
            },
            |(response, blinding)| {
                // Call the OPRF evaluate function here
                oprf::client::finalize_query(response, blinding)
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("OPRF/Client/FinalizeWithProofVerify", |b| {
        let rng = &mut rand::thread_rng();
        let key = OprfKey::random(rng);
        let pk = key.public_key();
        let server = OprfServer::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = oprf::client::blind_query(q, rng);
                let blinding = blinding.prepare();
                let (response, proof) = server.answer_query_with_proof(query);
                (response, proof, blinding)
            },
            |(response, proof, blinding)| {
                // Call the OPRF evaluate function here
                oprf::client::finalize_query_and_verify_proof(pk, response, proof, blinding)
            },
            BatchSize::SmallInput,
        );
    });
}
fn ddlog_bench(c: &mut Criterion) {
    c.bench_function("DDLOG/Server/Phase1", |b| {
        let rng = &mut rand::thread_rng();
        let x = ark_babyjubjub::Fr::rand(rng);
        let point = EdwardsAffine::rand(rng);

        b.iter(|| DLogSessionAdditive::partial_commitments(point, x.into(), rng));
    });
    c.bench_function("DDLOG/Server/Phase2", |b| {
        let rng = &mut rand::thread_rng();
        let x = ark_babyjubjub::Fr::rand(rng);
        let point = EdwardsAffine::rand(rng);
        let pk = (EdwardsProjective::generator() * x).into_affine();
        let session_id = Uuid::new_v4();
        let participating_parties = vec![1, 2, 3];

        b.iter_batched(
            || {
                let (session, comm) =
                    DLogSessionAdditive::partial_commitments(point, x.into(), rng);
                let challenge = DLogCommitmentsAdditive::combine_commitments(&[(1, comm)]);
                (session, challenge)
            },
            |(session, challenge)| {
                session.challenge(session_id, &participating_parties, x.into(), pk, challenge)
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("DDLOG/Server/Phase2Shamir", |b| {
        let rng = &mut rand::thread_rng();
        let x = ark_babyjubjub::Fr::rand(rng);
        let point = EdwardsAffine::rand(rng);
        let pk = (EdwardsProjective::generator() * x).into_affine();

        let session_id = Uuid::new_v4();
        let participating_parties = vec![1, 2, 3];

        b.iter_batched(
            || {
                let (session, comm) = DLogSessionShamir::partial_commitments(point, x.into(), rng);
                let challenge = DLogCommitmentsShamir::combine_commitments(
                    &[comm.clone(), comm.clone(), comm],
                    vec![1, 2, 3],
                );
                (session, challenge)
            },
            |(session, challenge)| {
                let lagrange = shamir::single_lagrange_from_coeff(1, &participating_parties);
                session.challenge(session_id, x.into(), pk, challenge, lagrange)
            },
            BatchSize::SmallInput,
        );
    });
    for set_size in [3, 5, 7, 10, 20, 30] {
        c.bench_function(&format!("DDLOG/Client/Phase1 (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);

            b.iter_batched(
                || {
                    let (_session, comm) =
                        DLogSessionAdditive::partial_commitments(point, x.into(), rng);
                    vec![(1, comm); set_size]
                },
                |commitments| DLogCommitmentsAdditive::combine_commitments(&commitments),
                BatchSize::SmallInput,
            );
        });
        c.bench_function(&format!("DDLOG/Client/Phase2 (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);
            let pk = (EdwardsProjective::generator() * x).into_affine();
            let session_id = Uuid::new_v4();
            let participating_parties = (1u16..=set_size as u16).collect::<Vec<_>>();

            b.iter_batched(
                || {
                    let (sessions, commitments) = (0..set_size)
                        .map(|i| {
                            let (session, comm) =
                                DLogSessionAdditive::partial_commitments(point, x.into(), rng);
                            (session, (i as u16 + 1, comm))
                        })
                        .collect::<(Vec<_>, Vec<_>)>();
                    let challenge = DLogCommitmentsAdditive::combine_commitments(&commitments);
                    let responses = sessions
                        .into_iter()
                        .map(|s| {
                            s.challenge(
                                session_id,
                                &participating_parties,
                                x.into(),
                                pk,
                                challenge.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    (challenge, responses)
                },
                |(challenge, responses)| {
                    challenge.combine_proofs(
                        session_id,
                        &participating_parties,
                        &responses,
                        pk,
                        point,
                    )
                },
                BatchSize::SmallInput,
            );
        });
        c.bench_function(&format!("DDLOG/Client/Phase1Shamir (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);

            b.iter_batched(
                || {
                    let (_session, comm) =
                        DLogSessionShamir::partial_commitments(point, x.into(), rng);
                    let used_parties = (1..=set_size as u16 * 2).choose_multiple(rng, set_size);
                    (vec![comm; set_size], used_parties)
                },
                |(commitments, used_parties)| {
                    DLogCommitmentsShamir::combine_commitments(&commitments, used_parties)
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, oprf_bench, ddlog_bench);

criterion_main!(benches);
