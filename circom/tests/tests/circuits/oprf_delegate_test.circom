pragma circom 2.2.2;

include "client_side_proofs/oprf_delegate.circom";

component main {public [cred_pk, current_time_stamp, merkle_root, depth, oprf_pk, nonce, mpc_public_keys, rp_merkle_root, rp_depth, expiration]} = OprfDelegate(10, 10);
