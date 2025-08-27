pragma circom 2.2.2;

include "babyjubjub/babyjubjub.circom";

template BabyJubJubIsInFrTest() {
    signal input in;
    signal output out;

    BabyJubJubScalarField() result <== BabyJubJubIsInFr()(in);
    out <== result.f;
}

component main = BabyJubJubIsInFrTest();