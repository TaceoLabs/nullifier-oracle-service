include "client_side_proofs/oprf_nullifier.circom";

component main {public [nonce, merkle_root, oprf_pk, nullified_action, nullified_epoch]} = OprfNullifier(30);
