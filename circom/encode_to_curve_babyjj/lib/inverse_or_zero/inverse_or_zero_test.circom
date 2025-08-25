pragma circom 2.2.2;

include "inverse_or_zero.circom";

template Tester() {
    signal input in;
    signal output out;

    signal kat0 <== InverseOrZero()(0);
    signal kat1 <== InverseOrZero()(1);
    signal kat2 <== InverseOrZero()(2);
    signal kat3 <== InverseOrZero()(-1);
    signal kat4 <== InverseOrZero()(-2);
    signal kat5 <== InverseOrZero()(0x42);
    signal kat6 <== InverseOrZero()(0x48329);
    assert(kat0 == 0);
    assert(kat1 == 1);
    assert(kat2 == 10944121435919637611123202872628637544274182200208017171849102093287904247809);
    assert(kat3 == 21888242871839275222246405745257275088548364400416034343698204186575808495616);
    assert(kat4 == 10944121435919637611123202872628637544274182200208017171849102093287904247808);
    assert(kat5 == 19566762567250261183523302105608776215520507570068879186033243136484434867294);
    assert(kat6 == 3300619213325833471365354409724901741924439636372635759680692339373852476642);
    out<== InverseOrZero()(in);
}

component main = Tester();
