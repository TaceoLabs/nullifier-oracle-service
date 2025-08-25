
pragma circom 2.2.2;

include "encode_to_curve.circom";

template Tester() {
    signal input in;
    signal output out;

    signal hash_to_field_test1 <== HashToField()(in);
    hash_to_field_test1 === 0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3;

    signal pow_const_5 <== PowConst((-1) >> 1)(5);
    pow_const_5 === 21888242871839275222246405745257275088548364400416034343698204186575808495616;

    signal is_zero_or_one0 <== IsZeroOrOne()(0);
    signal is_zero_or_one1 <== IsZeroOrOne()(1);
    signal is_zero_or_one2 <== IsZeroOrOne()(2);
    signal is_zero_or_one3 <== IsZeroOrOne()(-1);
    signal is_zero_or_one4 <== IsZeroOrOne()(431);
    assert(is_zero_or_one0 == 1);
    assert(is_zero_or_one1 == 1);
    assert(is_zero_or_one2 == 0);
    assert(is_zero_or_one3 == 0);
    assert(is_zero_or_one4 == 0);

    signal quadratic_residue0 <== IsQuadraticResidueOrZero()(0);
    signal quadratic_residue1 <== IsQuadraticResidueOrZero()(1);
    signal quadratic_residue2 <== IsQuadraticResidueOrZero()(2);
    signal quadratic_residue3 <== IsQuadraticResidueOrZero()(3);
    signal quadratic_residue4 <== IsQuadraticResidueOrZero()(4);
    signal quadratic_residue5 <== IsQuadraticResidueOrZero()(213219);

    // signal quadratic_non_residue0 <== IsQuadraticResidueOrZero()(-1);
    // signal quadratic_non_residue1 <== IsQuadraticResidueOrZero()(-2);
    // signal quadratic_non_residue2 <== IsQuadraticResidueOrZero()(-3);
    // signal quadratic_non_residue3 <== IsQuadraticResidueOrZero()(-4);
    // signal quadratic_non_residue4 <== IsQuadraticResidueOrZero()(-213219);

    assert(quadratic_residue0 == 1);
    assert(quadratic_residue1 == 1);
    assert(quadratic_residue2 == 1);
    assert(quadratic_residue3 == 1);
    assert(quadratic_residue4 == 1);
    assert(quadratic_residue5 == 1);

    signal sgn0_0 <== Sgn0()(0);
    signal sgn0_1 <== Sgn0()(1);
    signal sgn0_2 <== Sgn0()(2);
    signal sgn0_3 <== Sgn0()(3);
    signal sgn0_4 <== Sgn0()(4);
    signal sgn0_5 <== Sgn0()(-1);
    signal sgn0_6 <== Sgn0()(-2);
    signal sgn0_7 <== Sgn0()(-3);
    signal sgn0_8 <== Sgn0()(-4);

    assert(sgn0_0 == 0);
    assert(sgn0_1 == 1);
    assert(sgn0_2 == 0);
    assert(sgn0_3 == 1);
    assert(sgn0_4 == 0);
    assert(sgn0_5 == 1);
    assert(sgn0_6 == 0);
    assert(sgn0_7 == 1);
    assert(sgn0_8 == 0);


    // assert(quadratic_non_residue0 == 0);
    // assert(quadratic_non_residue1 == 0);
    // assert(quadratic_non_residue2 == 0);
    // assert(quadratic_non_residue3 == 0);
    // assert(quadratic_non_residue4 == 0);

    // signal map_to_curve_elligator2_test1[2] <== MapToCurveElligator2()(in);
    // map_to_curve_elligator2_test1 === [0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3, 3];
    // 



    out <== pow_const_5;
}

component main = Tester();