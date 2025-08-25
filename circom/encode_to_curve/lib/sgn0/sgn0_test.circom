pragma circom 2.2.2;

include "sgn0.circom";

template Tester() {
    signal input in;
    signal output out;

    signal kat1 <== Sgn0()(0);
    signal kat2 <== Sgn0()(1);
    signal kat3 <== Sgn0()(2);
    signal kat4 <== Sgn0()(3);
    signal kat5 <== Sgn0()(4);
    signal kat6 <== Sgn0()(-1);
    signal kat7 <== Sgn0()(-2);
    signal kat8 <== Sgn0()(-3);
    signal kat9 <== Sgn0()(-4);
    signal kat10 <== Sgn0()(-5);
    signal kat11 <== Sgn0()(0x42);
    signal kat12 <== Sgn0()(0x348598972154312);
    assert(kat1 == 0);
    assert(kat2 == 1);
    assert(kat3 == 0);
    assert(kat4 == 1);
    assert(kat5 == 0);
    assert(kat6 == 0);
    assert(kat7 == 1);
    assert(kat8 == 0);
    assert(kat9 == 1);
    assert(kat10 == 0);
    assert(kat11 == 0);
    assert(kat12 == 0);
    out<== Sgn0()(in);
}

component main = Tester();
