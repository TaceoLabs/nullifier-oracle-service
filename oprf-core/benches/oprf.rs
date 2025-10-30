use std::vec;

use ark_babyjubjub::{EdwardsAffine, EdwardsProjective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use criterion::*;
use oprf_core::{
    ddlog_equality::{DLogEqualityCommitments, DLogEqualitySession},
    oprf::{OPrfKey, OPrfService, OprfClient},
    shamir,
};
use rand::seq::IteratorRandom;
use uuid::Uuid;

fn oprf_bench(c: &mut Criterion) {
    c.bench_function("OPRF Client Query", |b| {
        let rng = &mut rand::thread_rng();
        let request_id = Uuid::new_v4();
        let pk = ark_babyjubjub::EdwardsAffine::rand(rng);
        let client = OprfClient::new(pk);
        let query = ark_babyjubjub::Fq::rand(rng);

        b.iter(|| client.blind_query(request_id, query, rng));
    });

    c.bench_function("OPRF/Server/Response", |b| {
        let rng = &mut rand::thread_rng();
        let request_id = Uuid::new_v4();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OprfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = client.blind_query(request_id, q, rng);
                query
            },
            |query| server.answer_query(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Server/ResponseWithProof", |b| {
        let rng = &mut rand::thread_rng();
        let request_id = Uuid::new_v4();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OprfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = client.blind_query(request_id, q, rng);
                query
            },
            |query| server.answer_query_with_proof(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Client/Finalize", |b| {
        let rng = &mut rand::thread_rng();
        let request_id = Uuid::new_v4();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OprfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = client.blind_query(request_id, q, rng);
                let blinding = blinding.prepare();
                let response = server.answer_query(query);
                (response, blinding)
            },
            |(response, blinding)| {
                // Call the OPRF evaluate function here
                client.finalize_query(response, blinding).unwrap()
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("OPRF/Client/FinalizeWithProofVerify", |b| {
        let rng = &mut rand::thread_rng();
        let request_id = Uuid::new_v4();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OprfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = client.blind_query(request_id, q, rng);
                let blinding = blinding.prepare();
                let (response, proof) = server.answer_query_with_proof(query);
                (response, proof, blinding)
            },
            |(response, proof, blinding)| {
                // Call the OPRF evaluate function here
                client
                    .finalize_query_and_verify_proof(response, proof, blinding)
                    .unwrap()
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

        b.iter(|| DLogEqualitySession::partial_commitments(point, x, rng));
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
                let (session, comm) = DLogEqualitySession::partial_commitments(point, x, rng);
                let challenge = DLogEqualityCommitments::combine_commitments(&[(1, comm)]);
                (session, challenge)
            },
            |(session, challenge)| {
                session.challenge(session_id, &participating_parties, x, pk, challenge)
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
                let (session, comm) = DLogEqualitySession::partial_commitments(point, x, rng);
                let challenge = DLogEqualityCommitments::combine_commitments(&[
                    (1, comm.clone()),
                    (2, comm.clone()),
                    (3, comm),
                ]);
                (session, challenge)
            },
            |(session, challenge)| {
                let lagrange = shamir::single_lagrange_from_coeff(1, &participating_parties);
                session.challenge_shamir(session_id, x, pk, challenge, lagrange)
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
                    let (_session, comm) = DLogEqualitySession::partial_commitments(point, x, rng);
                    vec![(1, comm); set_size]
                },
                |commitments| DLogEqualityCommitments::combine_commitments(&commitments),
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
                                DLogEqualitySession::partial_commitments(point, x, rng);
                            (session, (i as u16 + 1, comm))
                        })
                        .collect::<(Vec<_>, Vec<_>)>();
                    let challenge = DLogEqualityCommitments::combine_commitments(&commitments);
                    let responses = sessions
                        .into_iter()
                        .map(|s| {
                            s.challenge(
                                session_id,
                                &participating_parties,
                                x,
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
                    let (_session, comm) = DLogEqualitySession::partial_commitments(point, x, rng);
                    let used_parties = (1..=set_size as u16 * 2).choose_multiple(rng, set_size);
                    (vec![comm; set_size], used_parties)
                },
                |(commitments, used_parties)| {
                    DLogEqualityCommitments::combine_commitments_shamir(&commitments, used_parties)
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, oprf_bench, ddlog_bench);

criterion_main!(benches);
