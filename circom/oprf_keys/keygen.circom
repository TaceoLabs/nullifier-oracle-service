pragma circom 2.0.0;

include "babyjubjub/babyjubjub.circom";
include "poseidon2/poseidon2.circom";

// calculates (a + b) % p, where a, b < p and p = BabyJubJub ScalarField
template AddModP() {
    signal input a;
    signal input b;
    signal output out;

    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal sum <== a + b; // No overflow
    out <-- sum % fr;
    signal x <-- sum \ fr;
    sum === x * fr + out;

    // We constrain out to be < p
    signal bits[251] <== Num2Bits(251)(out);
    // CompConstant enforces <=, so compare against (fr - 1).
    component cmp_const = CompConstant(fr-1);
    for(var i=0; i<251; i++) {
        cmp_const.in[i] <== bits[i];
    }
    cmp_const.in[251] <== 0;
    cmp_const.in[252] <== 0;
    cmp_const.in[253] <== 0;
    cmp_const.out === 0;

    // x must either be 0 or 1
    x * (x - 1) === 0;
}

// calculates (a + b + c) % p, where a, b, c < p and p = BabyJubJub ScalarField
template Add3ModP() {
    signal input a;
    signal input b;
    signal input c;
    signal output out;

    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal sum <== a + b + c; // No overflow
    out <-- sum % fr;
    signal x <-- sum \ fr;
    sum === x * fr + out;

    // We constrain out to be < p
    signal bits[251] <== Num2Bits(251)(out);
    // CompConstant enforces <=, so compare against (fr - 1).
    component cmp_const = CompConstant(fr-1);
    for(var i=0; i<251; i++) {
        cmp_const.in[i] <== bits[i];
    }
    cmp_const.in[251] <== 0;
    cmp_const.in[252] <== 0;
    cmp_const.in[253] <== 0;
    cmp_const.out === 0;

    // x must either be 0 or 1 or 2
    signal zero_or_one <== x * (x - 1);
    zero_or_one * (x - 2) === 0;
}


function log_ceil(n) {
   var n_temp = n;
   for (var i = 0; i < 254; i++) {
       if (n_temp == 0) {
          return i;
       }
       n_temp = n_temp \ 2;
   }
   return 254;
}

// Implement a * B mod P (= BabyJubJub ScalarField) via a double-add-ladder.
template MulModP(B) {
    assert(B > 0);
    var B_NUM_BITS = log_ceil(B);
    assert(B < 2**B_NUM_BITS);

    signal input a;
    signal output out;

    var b_bits[B_NUM_BITS];
    for (var i = 0; i<B_NUM_BITS; i++) {
        b_bits[i] = (B >> i) & 1;
    }

    var init = 0;
    if (b_bits[B_NUM_BITS - 1] == 1) {
        init = a;
    }

    signal result[B_NUM_BITS];
    result[0] <== init;
    component dbl[B_NUM_BITS-1];
    component dbladd[B_NUM_BITS-1];
    for(var i = 0; i < B_NUM_BITS - 1; i++) {
        var tmp = 0;
        if (b_bits[B_NUM_BITS - 2 - i] == 1 ){
            // double and add
            dbladd[i] = Add3ModP();
            dbladd[i].a <== result[i];
            dbladd[i].b <== result[i];
            dbladd[i].c <== a;
            tmp = dbladd[i].out;
        } else {
            // only double
            dbl[i] = AddModP();
            dbl[i].a <== result[i];
            dbl[i].b <== result[i];
            tmp = dbl[i].out;
        }
        result[i + 1] <== tmp;
    }
    out <== result[B_NUM_BITS - 1];
}

// Evaluates a polynomial mod P (= BabyJubJub ScalarField) at an index
template EvalPolyModP(DEGREE, INDEX) {
    assert(DEGREE >= 1);
    assert(INDEX > 0);
    input BabyJubJubScalarField() poly[DEGREE + 1];
    signal output out;

    if (INDEX == 1) {
        // Just add all the coefficients
        component adder_modp[DEGREE];
        adder_modp[0] = AddModP();
        adder_modp[0].a <== poly[0].f;
        adder_modp[0].b <== poly[1].f;

        for(var i = 1; i < DEGREE; i++) {
          adder_modp[i] = AddModP();
          adder_modp[i].a <== adder_modp[i-1].out;
          adder_modp[i].b <== poly[i+1].f;

        }
        out <== adder_modp[DEGREE-1].out;
    } else {
        // Use Horners rule
        component adder_modp[DEGREE];
        component mult_modp[DEGREE];

        mult_modp[0] = MulModP(INDEX);
        mult_modp[0].a <== poly[DEGREE].f;
        adder_modp[0] = AddModP();
        adder_modp[0].a <== mult_modp[0].out;
        adder_modp[0].b <== poly[DEGREE-1].f;

        for(var i = 1; i < DEGREE; i++) {
            mult_modp[i] = MulModP(INDEX);
            mult_modp[i].a <== adder_modp[i-1].out;
            adder_modp[i] = AddModP();
            adder_modp[i].a <== mult_modp[i].out;
            adder_modp[i].b <== poly[DEGREE-1-i].f;
        }
        out <== adder_modp[DEGREE-1].out;
    }
}


// Checks outside of the ZK proof: The public keys pks need to be valid BabyJubJub points in the correct subgroup.

template KeyGen(DEGREE, NUM_PARTIES) {
    assert(DEGREE < NUM_PARTIES);
    assert(DEGREE >= 1);
    assert(NUM_PARTIES >= 3);
    // My secret key and public key
    signal input my_sk;
    signal output my_pk[2]; // Public
    // All parties' public keys
    signal input pks[NUM_PARTIES][2]; // Public
    // Coefficients of the sharing polynomial
    signal input poly[DEGREE + 1];
    // Nonces used in the encryption of the shares
    signal input nonces[NUM_PARTIES]; // Public
    // Commitments to the poly
    signal output comm_input_share[2]; // Public
    signal output comm_coeffs; // Public
    // Outputs are all the ciphertexts and the commitments to the shares
    signal output ciphertexts[NUM_PARTIES]; // Public
    signal output comm_shares[NUM_PARTIES]; // Public

    ////////////////////////////////////////////////////////////////////////////
    // Range check the secret inputs
    ////////////////////////////////////////////////////////////////////////////

    // Range check my sk
    component sk_f = BabyJubJubIsInFr();
    sk_f.in <== my_sk;

    // Range check the coefficients
    // TODO Do i need this range checks for all the coefficients?
    component poly_f[DEGREE+1];
    for (var i=0; i<DEGREE+1; i++) {
        poly_f[i] = BabyJubJubIsInFr();
        poly_f[i].in <== poly[i];
    }

    ////////////////////////////////////////////////////////////////////////////
    // Recompute my public key
    ////////////////////////////////////////////////////////////////////////////

    component my_pk_comp = BabyJubJubScalarGenerator();
    my_pk_comp.e <== sk_f.out;
    my_pk[0] <== my_pk_comp.out.x;
    my_pk[1] <== my_pk_comp.out.y;

    ////////////////////////////////////////////////////////////////////////////
    // Recompute the commitments to the polynomial coefficients
    ////////////////////////////////////////////////////////////////////////////

    // The input_share
    component comm_share_comp = BabyJubJubScalarGenerator();
    comm_share_comp.e <== poly_f[0].out;
    comm_input_share[0] <== comm_share_comp.out.x;
    comm_input_share[1] <== comm_share_comp.out.y;

    // The coefficients in a poseidon sponge
    // Pad the inputs to a multiple of 3
    var NUM_POSEIDONS = (DEGREE + 2) \ 3;
    var poseidon_inputs[NUM_POSEIDONS][3];
    for (var i=0; i<NUM_POSEIDONS; i++) {
        for (var j=0; j<3; j++) {
            poseidon_inputs[i][j] = 0;
        }
    }
    for (var i=0; i<DEGREE; i++) {
        poseidon_inputs[i\3][i%3] = poly_f[i + 1].out.f;
    }

    // Finally the poseidon sponge
    component poseidon2_sponge[NUM_POSEIDONS];
    poseidon2_sponge[0] = Poseidon2(4);
    poseidon2_sponge[0].in[0] <== 391480396463803266015599265965237862; // Domain separator in capacity b"KeyGenPolyCoeff"
    poseidon2_sponge[0].in[1] <== poseidon_inputs[0][0];
    poseidon2_sponge[0].in[2] <== poseidon_inputs[0][1];
    poseidon2_sponge[0].in[3] <== poseidon_inputs[0][2];
    for (var i=1; i<NUM_POSEIDONS; i++) {
        poseidon2_sponge[i] = Poseidon2(4);
        poseidon2_sponge[i].in[0] <== poseidon2_sponge[i-1].out[0];
        poseidon2_sponge[i].in[1] <== poseidon2_sponge[i-1].out[1] + poseidon_inputs[i][0];
        poseidon2_sponge[i].in[2] <== poseidon2_sponge[i-1].out[2] + poseidon_inputs[i][1];
        poseidon2_sponge[i].in[3] <== poseidon2_sponge[i-1].out[3] + poseidon_inputs[i][2];
    }
    comm_coeffs <== poseidon2_sponge[NUM_POSEIDONS - 1].out[1];

    ////////////////////////////////////////////////////////////////////////////
    // Derive the shares
    ////////////////////////////////////////////////////////////////////////////

    signal shares[NUM_PARTIES];
    component eval_poly[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        eval_poly[i] = EvalPolyModP(DEGREE, i+1);
        for (var j=0; j<DEGREE+1; j++) {
            eval_poly[i].poly[j] <== poly_f[j].out;
        }
        shares[i] <== eval_poly[i].out;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Encrypt the shares
    ////////////////////////////////////////////////////////////////////////////

    // Derive the symmetric keys for encryption
    component sym_keys[NUM_PARTIES];
    BabyJubJubPoint() { twisted_edwards } pk_p[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        pk_p[i].x <== pks[i][0];
        pk_p[i].y <== pks[i][1];
        sym_keys[i] = BabyJubJubScalarMul();
        sym_keys[i].p <== pk_p[i];
        sym_keys[i].e <== sk_f.out;
    }

    // Encrypt the shares with the derived symmetric keys
    var T1_DS = 0x80000002000000014142;
    component poseidon2_encrypt[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        poseidon2_encrypt[i] = Poseidon2(3);
        poseidon2_encrypt[i].in[0] <== T1_DS; // Domain separator in the capacity
        poseidon2_encrypt[i].in[1] <== sym_keys[i].out.x;
        poseidon2_encrypt[i].in[2] <== nonces[i];
        ciphertexts[i] <== poseidon2_encrypt[i].out[1] + shares[i];
    }

    ////////////////////////////////////////////////////////////////////////////
    // Commit to the shares
    ////////////////////////////////////////////////////////////////////////////
    component poseidon2_commit[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        poseidon2_commit[i] = Poseidon2(2);
        poseidon2_commit[i].in[0] <== 391480396463803266015599334567015013; // Domain separator in capacity b"KeyGenPolyShare"
        poseidon2_commit[i].in[1] <== shares[i];
        comm_shares[i] <== poseidon2_commit[i].out[1];
    }
}

// component main {public [pks, nonces]}  = KeyGen(1, 3);
// component main {public [pks, nonces]} = KeyGen(15, 30);
