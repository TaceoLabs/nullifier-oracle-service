# Nullifier Oracle Service

> [!WARNING]
> This repository is heavy WIP and may contain incomplete, insecure and unaudited protocols. Do not use this in production!

This is a monorepo containing:

* `ark-babyjubjub`: An implementation of the BabyJubJub elliptic curve using the arkworks ecosystem. It is compatible with EIP-2494, in contrast to `ark-ed-on-bn254`.
* `ark-serde-compat`: A compatibility layer between `ark-serialize` and `serde`.
* `circom`: A collection of Circom circuits and test vectors for them.
* `contracts`: An implementation of the required smart contracts.
* `docs`: A typst document serving as a writeup of the overall scheme.
* `eddsa-babyjubjub`: An implementation of EdDSA on the BabyJubJub curve.
* `noir`: A collection of Noir circuits.
* `oprf-client`: A crate implementing a client for the REST API service.
* `oprf-core`: A crate implementing a verifiable OPRF based on the TwoHashDH OPRF construction + a threshold variant of it.
* `oprf-dev-client`: A crate implementing a dev client binary.
* `oprf-service`: A crate implementing a REST API service that answers OPRF requests.
* `oprf-test`: A crate implementing integration tests and required mocks.
* `oprf-types`: A crate implementing types that are shared between client and service.
* `poseidon2`: A crate implementing the Poseidon2 hash function for various parameter sets, compatible with the Circom and Noir implementations thereof.

## Dev Dependencies

* [just](https://github.com/casey/just?tab=readme-ov-file#installation)
* docker-compose
* anvil and forge,  install with [foundryup](https://getfoundry.sh/introduction/installation/)

## Setup

### Forge

To install the dependencies for the smart contracts run the following command:

```bash
cd contracts && forge install
```

## Test & Run

For development, the best way to run/test the setup is with the integration tests.

```bash
just integration-tests
```

To use the dev client, you can start the setup using the following command:

```bash
just run-setup
```

This command does multiple things in order:

1. start `localstack` docker container
2. start `anvil` docker container
3. deploy the `AccountRegistry` and `RpRegistry` smart contracts
4. register the OPRF nodes at the `RpRegistry` contract
5. start `postgres` and `world-id-indexer` docker containers
6. start 3 OPRF nodes

Log files for all processes can be found in the created `logs` directory.
You can kill the setup with `Ctrl+C`, which kills all processes and stops all docker containers.
You can then use the dev client to send nullifier requests using the following command:

```bash
just run-dev-client test
```
