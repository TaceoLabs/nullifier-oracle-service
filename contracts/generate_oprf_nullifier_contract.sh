#! /bin/bash
set -e pipefail

# This script generates a nullifier contract for OPRF (Oblivious Pseudorandom Function).
snarkjs zkey export solidityverifier ../circom/main/OPRFNullifierProof.zkey src/nullifier_verify/OPRFNullifierProofVerifier.sol 
