pragma circom 2.2.2;

include "oprf_query.circom";
include "verify_dlog/verify_dlog.circom";

// Checks outside of the ZK proof: The public key oprf_pk needs to be a valid BabyJubJub point in the correct subgroup.

template OprfNullifier(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input nonce; // Public
    signal input user_pk[2];
    signal input query_s;
    signal input query_r[2];
    // Merkle proof
    signal input merkle_root; // Public
    signal input index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    // Dlog Equality Proof
    signal input dlog_e;
    signal input dlog_s;
    signal input oprf_pk[2]; // Public
    signal input oprf_response_blinded[2];
    // Unblinded response
    signal input oprf_response[2];
    // Nullifier computation
    signal input nullified_action; // Public
    signal input nullified_epoch; // Public
    signal output nullifier; // Public

    // 1-3. Show that the original query was computed correctly
    component oprf_query = OprfQuery(MAX_DEPTH);
    oprf_query.nonce <== nonce;
    oprf_query.pk <== user_pk;
    oprf_query.s <== query_s;
    oprf_query.r <== query_r;
    oprf_query.merkle_root <== merkle_root;
    oprf_query.index <== index;
    oprf_query.siblings <== siblings;
    oprf_query.beta <== beta;

    // 4. Check the dlog equality proof
    BabyJubJubBaseField() e;
    e.f <== dlog_e;
    component dlog_eq_verifier = VerifyDlog();
    dlog_eq_verifier.e <== e;
    dlog_eq_verifier.s <== dlog_s;
    dlog_eq_verifier.a <== oprf_pk;
    dlog_eq_verifier.b <== oprf_query.q;
    dlog_eq_verifier.c <== oprf_response_blinded;

    // 5. Unblind the OPRF response
    BabyJubJubScalarField() beta_f;
    beta_f.f <== beta;
    // The following checks that the oprf_response is on the curve.
    // We do not check the correct subgroup, since we compute p^beta_f and match it with the blinded response.
    component p_check = BabyJubJubCheck();
    p_check.x <== oprf_response[0];
    p_check.y <== oprf_response[1];

    component unblinder = BabyJubJubScalarMul();
    unblinder.e <== beta_f;
    unblinder.p <== p_check.p;
    oprf_response_blinded[0] === unblinder.out.x;
    oprf_response_blinded[1] === unblinder.out.y;

    // Hash the result to get the output of the OPRF
    var poseidon_result[4] = Poseidon2(4)([0, index, oprf_response[0], oprf_response[1]]);
    signal oprf_output <== poseidon_result[1];

    // 6. Compute the nullifier
     // TODO use t=8 here?
    component hash1 = Poseidon2(4);
    hash1.in[0] <== 0;
    hash1.in[1] <== oprf_output;
    hash1.in[2] <== nullified_action;
    hash1.in[3] <== nullified_epoch;
    component hash = Poseidon2(4);
    hash.in[0] <== hash1.out[0];
    hash.in[1] <== hash1.out[1] + index;
    hash.in[2] <== hash1.out[2];
    hash.in[3] <== hash1.out[3];

    // component hash = Poseidon2(8);
    // hash.in[0] <== 0;
    // hash.in[1] <== oprf_output;
    // hash.in[2] <== nullified_action;
    // hash.in[3] <== nullified_epoch;
    // hash.in[4] <== index;
    // hash.in[5] <== 0;
    // hash.in[6] <== 0;
    // hash.in[7] <== 0;

    nullifier <== hash.out[1];
}

// component main {public [nonce, merkle_root, oprf_pk, nullified_action, nullified_epoch]} = OprfNullifier(30);
