use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use criterion::*;
use oprf_core::oprf::{OPrfClient, OPrfKey, OPrfService};

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

criterion_group!(benches, oprf_bench);

criterion_main!(benches);
