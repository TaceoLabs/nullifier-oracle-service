use std::vec;

use ark_babyjubjub::{EdwardsAffine, EdwardsProjective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use criterion::*;
use oprf_core::{
    ddlog_equality::{DLogEqualityChallenge, DLogEqualitySession},
    ddlog_equality_shamir::lagrange_from_coeff,
    oprf::{OPrfClient, OPrfKey, OPrfService},
};
use rand::seq::IteratorRandom;

fn oprf_bench(c: &mut Criterion) {
    c.bench_function("OPRF Client Query", |b| {
        let rng = &mut rand::thread_rng();
        let pk = ark_babyjubjub::EdwardsAffine::rand(rng);
        let client = OPrfClient::new(pk);
        let query = ark_babyjubjub::Fq::rand(rng);

        b.iter(|| client.blind_query(query, rng));
    });

    c.bench_function("OPRF/Server/Response", |b| {
        let rng = &mut rand::thread_rng();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OPrfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = client.blind_query(q, rng);
                query
            },
            |query| server.answer_query(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Server/ResponseWithProof", |b| {
        let rng = &mut rand::thread_rng();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OPrfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, _) = client.blind_query(q, rng);
                query
            },
            |query| server.answer_query_with_proof(query),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("OPRF/Client/Finalize", |b| {
        let rng = &mut rand::thread_rng();
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OPrfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = client.blind_query(q, rng);
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
        let key = OPrfKey::random(rng);
        let pk = key.public_key().into_affine();
        let client = OPrfClient::new(pk);
        let server = OPrfService::new(key);
        let q = ark_babyjubjub::Fq::rand(rng);

        b.iter_batched(
            || {
                let (query, blinding) = client.blind_query(q, rng);
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

        b.iter(|| DLogEqualitySession::partial_commitments(point, x, uuid::Uuid::new_v4(), rng));
    });
    c.bench_function("DDLOG/Server/Phase2", |b| {
        let rng = &mut rand::thread_rng();
        let x = ark_babyjubjub::Fr::rand(rng);
        let point = EdwardsAffine::rand(rng);
        let pk = (EdwardsProjective::generator() * x).into_affine();

        b.iter_batched(
            || {
                let (session, comm) =
                    DLogEqualitySession::partial_commitments(point, x, uuid::Uuid::new_v4(), rng);
                let (_, e) = DLogEqualityChallenge::combine_commitments_and_create_challenge(
                    &[comm],
                    pk,
                    point,
                )
                .unwrap();
                (session, e)
            },
            |(session, e)| session.challenge(x, e).unwrap(),
            BatchSize::SmallInput,
        );
    });
    for set_size in [3, 5, 7, 10, 20, 30] {
        c.bench_function(&format!("DDLOG/Client/Phase1 (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);
            let pk = (EdwardsProjective::generator() * x).into_affine();

            b.iter_batched(
                || {
                    let (_session, comm) = DLogEqualitySession::partial_commitments(
                        point,
                        x,
                        uuid::Uuid::new_v4(),
                        rng,
                    );
                    vec![comm; set_size]
                },
                |commitments| {
                    DLogEqualityChallenge::combine_commitments_and_create_challenge(
                        &commitments,
                        pk,
                        point,
                    )
                    .unwrap()
                },
                BatchSize::SmallInput,
            );
        });
        c.bench_function(&format!("DDLOG/Client/Phase2 (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);
            let pk = (EdwardsProjective::generator() * x).into_affine();

            b.iter_batched(
                || {
                    let uuid = uuid::Uuid::new_v4();
                    let (sessions, commitments) = (0..set_size)
                        .map(|_| DLogEqualitySession::partial_commitments(point, x, uuid, rng))
                        .collect::<(Vec<_>, Vec<_>)>();
                    let (_, challenge) =
                        DLogEqualityChallenge::combine_commitments_and_create_challenge(
                            &commitments,
                            pk,
                            point,
                        )
                        .unwrap();
                    let responses = sessions
                        .into_iter()
                        .map(|s| s.challenge(x, challenge.clone()).unwrap())
                        .collect::<Vec<_>>();
                    (challenge, responses)
                },
                |(challenge, responses)| challenge.combine_proofs(&responses).unwrap(),
                BatchSize::SmallInput,
            );
        });
        c.bench_function(&format!("DDLOG/Client/Phase1Shamir (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);
            let pk = (EdwardsProjective::generator() * x).into_affine();

            b.iter_batched(
                || {
                    let (_session, comm) = DLogEqualitySession::partial_commitments(
                        point,
                        x,
                        uuid::Uuid::new_v4(),
                        rng,
                    );
                    let used_parties = (1..=set_size * 2).choose_multiple(rng, set_size);
                    let lagrange = lagrange_from_coeff(&used_parties);
                    (vec![comm; set_size], lagrange)
                },
                |(commitments, lagrange)| {
                    DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
                        &commitments,
                        &lagrange,
                        pk,
                        point,
                    )
                    .unwrap()
                },
                BatchSize::SmallInput,
            );
        });
        c.bench_function(&format!("DDLOG/Client/Phase2Shamir (t={set_size})"), |b| {
            let rng = &mut rand::thread_rng();
            let x = ark_babyjubjub::Fr::rand(rng);
            let point = EdwardsAffine::rand(rng);
            let pk = (EdwardsProjective::generator() * x).into_affine();

            b.iter_batched(
                || {
                    let uuid = uuid::Uuid::new_v4();
                    let (sessions, commitments) = (0..set_size)
                        .map(|_| DLogEqualitySession::partial_commitments(point, x, uuid, rng))
                        .collect::<(Vec<_>, Vec<_>)>();
                    let used_parties = (1..=set_size * 2).choose_multiple(rng, set_size);
                    let lagrange = lagrange_from_coeff(&used_parties);
                    let (_, challenge) =
                        DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
                            &commitments,
                            &lagrange,
                            pk,
                            point,
                        )
                        .unwrap();
                    let responses = sessions
                        .into_iter()
                        .map(|s| s.challenge(x, challenge.clone()).unwrap())
                        .collect::<Vec<_>>();
                    (challenge, responses, lagrange)
                },
                |(challenge, responses, lagrange)| {
                    challenge
                        .combine_proofs_shamir(&responses, &lagrange)
                        .unwrap()
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, oprf_bench, ddlog_bench);

criterion_main!(benches);
