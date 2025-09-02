pragma circom 2.2.2;

include "client_side_proofs/oprf_query.circom";

component main {public [nonce, merkle_root]} = OprfQuery(10);
