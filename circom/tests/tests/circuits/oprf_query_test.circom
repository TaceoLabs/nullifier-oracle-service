pragma circom 2.2.2;

include "client_side_proofs/oprf_query.circom";

component main {public [merkle_root, rp_id, action]} = OprfQuery(10);
