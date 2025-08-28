pragma circom 2.2.2;

include "babyjubjub/correct_sub_group.circom";

template ScalarMulFixScalarTestOneSuite() {
    signal input in[2];
    signal output out[2];
    var one[251];
    for (var i = 1;i<251;i++) {
        one[i] = 0;
    }
    one[0] = 1;

    out <== EscalarMulFixScalar(one)(in);
}

component main = ScalarMulFixScalarTestOneSuite();