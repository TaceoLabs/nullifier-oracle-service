use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};

fn ark_parse_bench(c: &mut Criterion) {
    c.bench_function("parse pk", |b| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let nullifier_pk_path = dir.join("../data/nullifier_pk.bin");
        let nullifier_pk_bytes = std::fs::read(nullifier_pk_path).unwrap();

        b.iter(|| {
            let _nullifier_pk =
                oprf_client::zk::parse_pk_bytes(&nullifier_pk_bytes, "foo").unwrap();
        });
    });

    c.bench_function("parse matrices", |b| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let nullifier_matrices_path = dir.join("../data/nullifier_matrices.bin");
        let nullifier_matrices_bytes = std::fs::read(nullifier_matrices_path).unwrap();

        b.iter(|| {
            let _nullifier_matrices =
                oprf_client::zk::parse_matrices_bytes(&nullifier_matrices_bytes, "foo").unwrap();
        });
    });
}

criterion_group!(benches, ark_parse_bench);

criterion_main!(benches);
