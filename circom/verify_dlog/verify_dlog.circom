pragma circom 2.2.2;

include "../poseidon2/poseidon2.circom";
include "babyjubjub.circom";

// Poseidon sponge construction by hand to compute the challenge point e. We use state size 4 with capacity 1 and absorb all provided points and squeeze once. The challenge we output is the first element not counting the capacity from the squeeze.
template ComputeChallengeHash() {
    input BabyJubJubPoint() a;
    input BabyJubJubPoint() b;
    input BabyJubJubPoint() c;
    input BabyJubJubPoint() r1;
    input BabyJubJubPoint() r2;
    output signal challenge;

    signal ins[4][4];
    signal perms[4][4];
    ins[0] <== [0, a.x, a.y, b.x];

    perms[0] <== Poseidon2(4)(ins[0]);
    ins[1][0] <== perms[0][0];
    ins[1][1] <== perms[0][1] + b.y;
    ins[1][2] <== perms[0][2] + c.x;
    ins[1][3] <== perms[0][3] + c.y;

    perms[1] <== Poseidon2(4)(ins[1]);
    ins[2][0] <== perms[1][0];
    // We add the generator point to the sponge after adding A,B and C.
    ins[2][1] <== perms[1][1] + 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    ins[2][2] <== perms[1][2] + 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    ins[2][3] <== perms[1][3] + r1.x;

    perms[2] <== Poseidon2(4)(ins[2]);
    ins[3][0] <== perms[2][0];
    ins[3][1] <== perms[2][1] + r1.y;
    ins[3][2] <== perms[2][2] + r2.x;
    ins[3][3] <== perms[2][3] + r2.y;

    perms[3] <== Poseidon2(4)(ins[3]);
    challenge <== perms[3][1];
}


template VerifyDlog() {
    input BabyJubJubBaseField() e;
    input signal s;
    input signal a[2];
    input signal b[2];
    input signal c[2];

    // check if on curve
    // Point A is public input. This means we don't necessarily need to check this inside the circuit, but can delegate that to the verifier in Rust land.
    BabyJubJubPoint {twisted_edwards } a_p <== BabyJubJubCheck()(a[0], a[1]);
    BabyJubJubPoint {twisted_edwards } b_p <== BabyJubJubCheck()(b[0], b[1]);
    BabyJubJubPoint {twisted_edwards } c_p <== BabyJubJubCheck()(c[0], c[1]);

    // TODO we don't check whether the points are in the correct subgroup like we do in Rust. The points can be public, therefore we maybe add this check in Rust. 

    // check if not the identity
    BabyJubJubCheckNotIdentity()(a_p);
    BabyJubJubCheckNotIdentity()(b_p);
    BabyJubJubCheckNotIdentity()(c_p);

    // Check that proof.s is in field Fq. This check is required to prevent malleability of the proof by using different s, such as s + q 
    // Fq has 251 bits, therefore we call LessThan with 251
    BabyJubJubScalarField() s_f <== BabyJubJubIsInFr()(s);

    // The Rust implementation now converts e to Fr by doing a modulo reduction. We don't do this here because this is rather expensive. Therefore, we perform the segmentmul with 3 bits extra work, but the added constraints there are cheaper than doing the mod reduction.

    // compute
    // G * s - a * e
    BabyJubJubPoint() lhs_r1 <== BabyJubJubScalarGenerator()(s_f);
    BabyJubJubPoint() rhs_r1 <== BabyJubJubScalarMulBaseField()(e, a_p);

    BabyJubJubPoint() r1 <== BabyJubJubSub()(lhs_r1, rhs_r1);
    // check that r1 is not the identity element
    BabyJubJubCheckNotIdentity()(r1);

    // compute
    // b * s - c * e
    BabyJubJubPoint() lhs_r2 <== BabyJubJubScalarMul()(s_f, b_p);
    BabyJubJubPoint() rhs_r2 <== BabyJubJubScalarMulBaseField()(e, c_p);

    BabyJubJubPoint() r2 <== BabyJubJubSub()(lhs_r2, rhs_r2);
    // check that r1 is not the identity element
    BabyJubJubCheckNotIdentity()(r2);

    // recompute the challenge hash
    signal challenge <== ComputeChallengeHash()(a_p,b_p,c_p,r1,r2);
    challenge === e.f;
}
