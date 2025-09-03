# Nullifier Oracle Service

> [!WARNING]
> This repository is heavy WIP and may contain incomplete, insecure and unaudited protocols. Do not use this in production!

This is a monorepo containing:

* `ark-babyjubjub`: An implementation of the BabyJubJub elliptic curve using the arkworks ecosystem. It is compatible with EIP-2494, in contrast to `ark-ed-on-bn254`.
* `circom`: A collection of Circom circuits and test vectors for them.
* `docs`: A typst document serving as a writeup of the overall scheme.
* `eddsa-babyjubjub`: An implementation of EdDSA on the BabyJubJub curve.
* `noir`: A collection of Noir circuits.
* `oprf-core`: A crate implementing a verifiable OPRF based on the TwoHashDH OPRF construction + a threshold variant of it.
* `oprf-service`: A crate implementing a REST API service that answers OPRF requests.
* `poseidon2`: A crate implementing the Poseidon2 hash function for various parameter sets, compatible with the Circom and Noir implementations thereof.
