pragma circom 2.2.2;

include "client_side_proofs/oprf_rpid_query.circom";

component main {public [merkle_root, nonce]} = OprfRpIdQuery(10);
