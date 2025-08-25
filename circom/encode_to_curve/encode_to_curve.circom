
pragma circom 2.2.2;

include "../poseidon2/poseidon2.circom";
include "../circomlib/mux1.circom";
include "../circomlib/bitify.circom";
include "../circomlib/comparators.circom";




template IsZeroOrOne() {
    signal input in;
    signal output out;
    out <== IsZero()(in * in - in);
}

template InverseOrZero() {
    signal input in;
    signal output inv;

    inv <-- in != 0 ? 1/in : 0;
    signal in_square <== in * in;
    in_square * inv - in === 0;
}

template HashToField() {
    signal input in;
    signal output out;

    component hasher = Poseidon2(3);
    hasher.in <== [0,in,0];
    out <== hasher.out[1];
}


template MapToCurveElligator2() {
    signal input in;
    signal output out[2];

    // var j = 168698;
    // var k = 168700;
    // var c1 = j / k;
    // var c2 = (k*k).inverse();
    var c1 = 0xabadec0c1080b603d2fe96f73c22330924c5f774700d414b9b615837d940a3a;
    var c2 = 0xf62ddd47ad2f3a2392b49b4fbbd128bebcab88509cd1bcfe8c451ee75c32c1;
    var z = 5;
    signal tv1_0 <== z * (in * in);
    signal e <== IsZero()(tv1_0 + 1);

    signal tv1 <== Mux1()([0, tv1_0], e);
    component x1_inv_zero = InverseOrZero();
    x1_inv_zero.in <== tv1 + 1;
    signal x1 <== -c1 * x1_inv_zero.inv;

    signal gx1_0 <== (x1 + c1) * x1;
    signal gx1 <== (gx1_0 + c2) * x1;
    signal x2 <== -x1 - c1;
    signal gx2 <== tv1 * gx1;
    signal e2 <== IsQuadraticResidueOrZero()(gx1);

    signal x <== Mux1()([x1,x2], e2);
    signal y2 <== Mux1()([gx1,gx2], e2);

    signal y <-- sqrt(y2);
    y*y === y2;

    signal e3 <== Sgn0()(y);

    
    
    out[0] <== e2;
    out[1] <== tv1;

}

template EncodeToCurveBabyJubJub() {
    signal input in;
    signal output out;
    signal u <== HashToField()(in);
    signal a <== MapToCurveElligator2()(u);

    out <== u;
}