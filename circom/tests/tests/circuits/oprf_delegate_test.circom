pragma circom 2.2.2;

include "client_side_proofs/oprf_delegate.circom";

component main {public [merkle_root, oprf_pk, nonce, mpc_public_keys, rp_merkle_root, expiration]} = OprfDelegate(10);
