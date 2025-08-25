pragma circom 2.2.2;
include "quadratic_residue.circom";

template Tester() {
    signal input in;
    signal output out;

    // unit tests for gadgets
    signal is_zero_or_one_kat1 <== IsZeroOrOne()(0);
    signal is_zero_or_one_kat2 <== IsZeroOrOne()(1);
    signal is_zero_or_one_kat3 <== IsZeroOrOne()(2);
    signal is_zero_or_one_kat4 <== IsZeroOrOne()(-1);

    assert(is_zero_or_one_kat1 == 1);
    assert(is_zero_or_one_kat2 == 1);
    assert(is_zero_or_one_kat3 == 0);
    assert(is_zero_or_one_kat4 == 0);

    // Because this only adds constraints and does not return anything
    // we only can check the happy case. In case you want to check the
    // unhappy case, uncomment the corresponding line and let the witness
    // extension crash 
    CheckZeroOneOrMinusOne()(0);
    CheckZeroOneOrMinusOne()(1);
    CheckZeroOneOrMinusOne()(-1);
    // CheckZeroOneOrMinusOne()(-1);

    out <== is_zero_or_one_kat4;

    signal is_quadratic_residue_kat0 <== IsQuadraticResidueOrZero()(0);
    signal is_quadratic_residue_kat1 <== IsQuadraticResidueOrZero()(1);
    signal is_quadratic_residue_kat2 <== IsQuadraticResidueOrZero()(2);
    signal is_quadratic_residue_kat3 <== IsQuadraticResidueOrZero()(3);
    signal is_quadratic_residue_kat4 <== IsQuadraticResidueOrZero()(4);
    signal is_quadratic_residue_kat5 <== IsQuadraticResidueOrZero()(5);

    signal is_quadratic_residue_kat6 <== IsQuadraticResidueOrZero()(-1);
    signal is_quadratic_residue_kat7 <== IsQuadraticResidueOrZero()(-2);
    signal is_quadratic_residue_kat8 <== IsQuadraticResidueOrZero()(-3);
    signal is_quadratic_residue_kat9 <== IsQuadraticResidueOrZero()(-4);
    signal is_quadratic_residue_kat10 <== IsQuadraticResidueOrZero()(-5);
    signal is_quadratic_residue_kat11 <== IsQuadraticResidueOrZero()(5*5*5);

    signal is_quadratic_residue_kat12 <== IsQuadraticResidueOrZero()(7);
    signal is_quadratic_residue_kat13 <== IsQuadraticResidueOrZero()(10);
    signal is_quadratic_residue_kat14 <== IsQuadraticResidueOrZero()(11);

    assert(is_quadratic_residue_kat0 == 1);
    assert(is_quadratic_residue_kat1 == 1);
    assert(is_quadratic_residue_kat2 == 1);
    assert(is_quadratic_residue_kat3 == 1);
    assert(is_quadratic_residue_kat4 == 1);
    assert(is_quadratic_residue_kat5 == 0);

    assert(is_quadratic_residue_kat6 == 1);
    assert(is_quadratic_residue_kat7 == 1);
    assert(is_quadratic_residue_kat8 == 1);
    assert(is_quadratic_residue_kat9 == 1);
    assert(is_quadratic_residue_kat10 == 0);
    assert(is_quadratic_residue_kat11 == 0);
    assert(is_quadratic_residue_kat12 == 0);
    assert(is_quadratic_residue_kat13 == 0);
    assert(is_quadratic_residue_kat14 == 0);
}

component main = Tester();