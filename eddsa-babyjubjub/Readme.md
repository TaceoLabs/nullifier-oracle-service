# EdDSA-BabyJubJub

An implementation of EdDSA on the BabyJubJub elliptic curve. The main use-case of this variant of EdDSA is to be efficiently verifiable in ZK proof systems using the BN254 scalar field (=BabyJubJub Base Field).
Accompanying Circom Circuits can be found in the `circom` folder of this monorepo.

Based on the MIT licensed reference implementation of the zk-kit <https://github.com/zk-kit/zk-kit/blob/main/packages/eddsa-poseidon/src/eddsa-poseidon-factory.ts>, modified to using Poseidon2 as the hash function.
