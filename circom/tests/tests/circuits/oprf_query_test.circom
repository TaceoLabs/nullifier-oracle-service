pragma circom 2.2.2;

include "client_side_proofs/oprf_query.circom";

component main {public [cred_pk, current_time_stamp, merkle_root, depth, depth, rp_id, action, nonce]} = OprfQuery(10);
