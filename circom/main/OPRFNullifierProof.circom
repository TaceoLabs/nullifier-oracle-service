include "client_side_proofs/oprf_nullifier.circom";

component main {public [merkle_root, rp_id, action, oprf_pk, signal_hash, nonce]} = OprfNullifier(30);
