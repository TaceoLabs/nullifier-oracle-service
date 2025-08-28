pragma circom 2.2.2;

include "babyjubjub/correct_sub_group.circom";

template ScalarMulFixScalarTestZeroSuite() {
    signal input in[2];
    signal output out[2];
    var zero[251];
    for (var i = 0;i<251;i++) {
        zero[i] = 0;
    }

    out <== EscalarMulFixScalar(zero)(in);
}

component main = ScalarMulFixScalarTestZeroSuite();