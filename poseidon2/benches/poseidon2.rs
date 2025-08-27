use criterion::*;
use poseidon2::{POSEIDON2_BN254_PARAMS_3, POSEIDON2_BN254_PARAMS_4, Poseidon2};

fn poseidon2_bench(c: &mut Criterion) {
    c.bench_function("Poseidon2 Permutation (t=3)", |b| {
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN254_PARAMS_3);
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
        ];

        b.iter(|| poseidon2.permutation(&input));
    });
    c.bench_function("Poseidon2 Permutation (t=4)", |b| {
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN254_PARAMS_4);
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
            ark_bn254::Fr::from(45u64),
        ];

        b.iter(|| poseidon2.permutation(&input));
    });
}

criterion_group!(benches, poseidon2_bench);
criterion_main!(benches);
