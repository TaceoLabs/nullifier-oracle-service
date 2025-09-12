include "client_side_proofs/oprf_query.circom";

component main {public [merkle_root, rp_id, action, nonce]} = OprfQuery(30);
