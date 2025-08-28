pragma circom 2.2.2;

include "babyjub.circom";
include "escalarmulany.circom";
include "comparators.circom";
include "compconstant.circom";
include "bitify.circom";


// Utilities for working with the BabyJubJub curve in Circom 2.x, using Twisted Edwards form.
// This file defines:
// - Buses for points and field elements.
// - Checks and helpers for constructing valid points and field elements.
// - Basic group operations (negation, subtraction).
// - Scalar multiplication variants (fixed-base, arbitrary-base, and base-field exponent).

// A point on the BabyJubJub curve.
// See the template BabyJubJubCheck if you want to construct an instance of this bus safely.
bus BabyJubJubPoint {
    signal x;
    signal y;
}

// An element in the base field Fq of BabyJubJub.
// Since Fq is the ScalarField of BN254 (i.e., the field Circom operates over), we do not
// need additional range checks to construct an instance of this bus.
bus BabyJubJubBaseField {
    signal f;
}

// An element in the scalar field Fr of BabyJubJub.
// See the template BabyJubJubIsInFr if you want to construct an instance of this bus safely.
bus BabyJubJubScalarField {
    signal f;
}


// Checks whether two input signals representing the x and y coordinates define a valid
// BabyJubJub point in Twisted Edwards form, i.e., they satisfy:
//
//   a * x^2 + y^2 === 1 + d * x^2 * y^2
//
// where a = 168700 and d = 168696.
//
// If the check succeeds, outputs a BabyJubJubPoint bus tagged twisted_edwards.
// This template is the canonical way to obtain a point that can be safely used
// with the other templates defined in this file.
//
// Use this method to construct BabyJubJub points in Twisted Edwards form unless you explicitly
// know what you are doing.
template BabyJubJubCheck() {
    signal input x;
    signal input y;
    output BabyJubJubPoint() { twisted_edwards } p;
    BabyCheck()(x,y);
    p.x <== x;
    p.y <== y;
}

// Computes the negation -P of a point P in Twisted Edwards form.
// Negation is performed by negating the x-coordinate and keeping y unchanged.
template BabyJubJubNeg() {
    input BabyJubJubPoint() { twisted_edwards } in;
    output BabyJubJubPoint() { twisted_edwards } out;
    out.x <== -in.x;
    out.y <== in.y;
}

// Computes the subtraction P - Q for two points in Twisted Edwards form.
// Implemented as P + (-Q).
template BabyJubJubSub() {
    input BabyJubJubPoint() { twisted_edwards } lhs;
    input BabyJubJubPoint() { twisted_edwards } rhs;
    output BabyJubJubPoint() { twisted_edwards } out;

    BabyJubJubPoint() neg_rhs <== BabyJubJubNeg()(rhs);

    signal (res_x, res_y) <== BabyAdd()(lhs.x,lhs.y,neg_rhs.x,neg_rhs.y);
    out.x <== res_x;
    out.y <== res_y;
}

// Performs fixed-base scalar multiplication e·G, where G is the BabyJubJub generator.
// This is a thin wrapper around EscalarMulFix with the hardcoded generator.
template BabyJubJubScalarGenerator() {
    // do with generator (scalarmul fix)
    input BabyJubJubScalarField() e;
    output BabyJubJubPoint() { twisted_edwards } out;
    // The generator of BabyJubJub
    var GENERATOR[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    signal bits[251] <== Num2Bits(251)(e.f);
    signal result[2] <== EscalarMulFix(251, GENERATOR)(bits);
    out.x <== result[0];
    out.y <== result[1];
}

// Performs fixed-point scalar multiplication e·P for a constant point P.
// When P is known at compile time (e.g., the generator), prefer this over BabyJubJubScalarMul
// to reduce constraints.
template BabyJubJubScalarMulFix(BASE) {
    input BabyJubJubScalarField() e;
    output BabyJubJubPoint() { twisted_edwards } out;
    signal bits[251] <== Num2Bits(251)(e.f);
    signal result[2] <== EscalarMulFix(251, BASE)(bits);
    out.x <== result[0];
    out.x <== result[1];
}

// Performs scalar multiplication e·P for an arbitrary point P in Twisted Edwards form.
template BabyJubJubScalarMul() {
    input BabyJubJubScalarField() e;
    input BabyJubJubPoint() { twisted_edwards } p;
    output BabyJubJubPoint() { twisted_edwards } out;

    signal bits[251] <== Num2Bits(251)(e.f);
    signal result[2] <== EscalarMulAny(251)(bits, [p.x,p.y]); 
    out.x <== result[0];
    out.y <== result[1];
}

// Performs scalar multiplication e·P where e is provided in the base field Fq of BabyJubJub.
// The scalar field Fr has 251 bits. To avoid an explicit modular reduction in-circuit,
// we use a strict 254-bit decomposition. EscalarMulAny correctly handles the modular
// reduction internally despite the redundant high bits.
//
// This is useful for verifiers that provide scalars in Fq: reducing them to Fr in-circuit
// would be more expensive than letting EscalarMulAny handle the modular reduction.
template BabyJubJubScalarMulBaseField() {
    input BabyJubJubBaseField() e;
    input BabyJubJubPoint() { twisted_edwards } p;
    output BabyJubJubPoint() { twisted_edwards } out;

    signal bits[254] <== Num2Bits_strict()(e.f);
    // performs the module reduction correctly
    signal result[2] <== EscalarMulAny(254)(bits, [p.x,p.y]); 
    out.x <== result[0];
    out.y <== result[1];
}

// Asserts that an input signal lies in the BabyJubJub scalar field Fr.
// If the constraint holds, returns an instance of BabyJubJubScalarField.
// If the input is NOT in Fr, an assertion will fail.
//
// Use this to obtain an element of Fr unless you explicitly know what you are doing.
template BabyJubJubIsInFr() {
    signal input in;
    output BabyJubJubScalarField() out;
    // Prime order of BabyJubJub's scalar field Fr.
    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal bits[254] <== Num2Bits_strict()(in);
    // CompConstant enforces <=, so compare against (fr - 1).
    signal check <== CompConstant(fr - 1)(bits);    
    check === 0;
    out.f <== in;
}

// Adds constraints to ensure a provided Twisted Edwards point is NOT the identity element.
// The identity in Twisted Edwards form is (x = 0, y = 1).
template BabyJubJubCheckNotIdentity() {
    input BabyJubJubPoint() { twisted_edwards } p;
    signal x_check <== IsZero()(p.x);
    signal y_check <== IsZero()(1 - p.y);

    // At least one of the is zero check must be 0. If both are one, it is the identity element which fails the constraint.
    x_check * y_check === 0;
}

