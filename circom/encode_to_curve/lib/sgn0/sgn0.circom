include "bitify.circom";

template Sgn0() {
    signal input in;
    signal output out;

    signal bits[254] <== Num2Bits_strict()(in);
    out <== IsZero()(1 - bits[0]);
}
