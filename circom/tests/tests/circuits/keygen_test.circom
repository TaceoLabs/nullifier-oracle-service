pragma circom 2.2.2;

include "oprf_keys/keygen.circom";

component main {public [pks, nonces]} = KeyGen(5, 9);
