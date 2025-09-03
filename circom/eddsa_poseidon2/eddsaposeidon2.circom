/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

// This file is copied from https://github.com/iden3/circomlib/blob/master/circuits/eddsaposeidon.circom and adapted to use Poseidon2 instead of Poseidon and use a more standard cofactored verification.

include "circomlib/compconstant.circom";
include "poseidon2/poseidon2.circom";
include "circomlib/bitify.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/escalarmulfix.circom";

template EdDSAPoseidon2Verifier() {
    signal input Ax;
    signal input Ay;

    signal input S;
    signal input Rx;
    signal input Ry;

    signal input M;

    var i;

// Ensure S<Subgroup Order

    component snum2bits = Num2Bits(253);
    snum2bits.in <== S;

    component  compConstant = CompConstant(2736030358979909402780800718157159386076813972158567259200215660948447373040);

    for (i=0; i<253; i++) {
        snum2bits.out[i] ==> compConstant.in[i];
    }
    compConstant.in[253] <== 0;
    compConstant.out === 0;

// Calculate the h = H(R,A, msg)

    // TODO use t=8 here?
    component hash1 = Poseidon2(4);
    hash1.in[0] <== 0;
    hash1.in[1] <== Rx;
    hash1.in[2] <== Ry;
    hash1.in[3] <== Ax;
    component hash = Poseidon2(4);
    hash.in[0] <== hash1.out[0];
    hash.in[1] <== hash1.out[1] + Ay;
    hash.in[2] <== hash1.out[2] + M;
    hash.in[3] <== hash1.out[3];

    // component hash = Poseidon2(8);
    // hash.in[0] <== 0;
    // hash.in[1] <== Rx;
    // hash.in[2] <== Ry;
    // hash.in[3] <== Ax;
    // hash.in[4] <== Ay;
    // hash.in[5] <== M;
    // hash.in[6] <== 0;
    // hash.in[7] <== 0;

    component h2bits = Num2Bits_strict();
    h2bits.in <== hash.out[1];

// Calculate second part of the right side:  right2 = h*A


    // We check that A is not zero.
    component isZero = IsZero();
    isZero.in <== Ax;
    isZero.out === 0;

    component mulAny = EscalarMulAny(254);
    for (i=0; i<254; i++) {
        mulAny.e[i] <== h2bits.out[i];
    }
    mulAny.p[0] <== Ax;
    mulAny.p[1] <== Ay;


// Compute the right side: right =  R + right2

    component addRight = BabyAdd();
    addRight.x1 <== Rx;
    addRight.y1 <== Ry;
    addRight.x2 <== mulAny.out[0];
    addRight.y2 <== mulAny.out[1];

// Calculate left side of equation left = S*B

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    component mulFix = EscalarMulFix(253, BASE8);
    for (i=0; i<253; i++) {
        mulFix.e[i] <== snum2bits.out[i];
    }

    // compute v = s*B - R - h*A = s*B - (R + h*A)
    component v = BabyAdd();
    v.x1 <== mulFix.out[0];
    v.y1 <== mulFix.out[1];
    v.x2 <== -addRight.xout;
    v.y2 <== addRight.yout;

    // Multiply by 8 by adding it 3 times.  This also ensure that the result is in
    // the subgroup.
    component dbl1 = BabyDbl();
    dbl1.x <== v.xout;
    dbl1.y <== v.yout;
    component dbl2 = BabyDbl();
    dbl2.x <== dbl1.xout;
    dbl2.y <== dbl1.yout;
    component dbl3 = BabyDbl();
    dbl3.x <== dbl2.xout;
    dbl3.y <== dbl2.yout;

// Do the comparison 8*v == Identity;

    dbl3.xout === 0;
    dbl3.yout === 1;
}
