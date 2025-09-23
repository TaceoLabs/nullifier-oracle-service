pragma circom 2.2.2;

include "oprf_query.circom";
include "verify_dlog/verify_dlog.circom";

// Checks outside of the ZK proof: The public key oprf_pk needs to be a valid BabyJubJub point in the correct subgroup.

template OprfNullifier(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input user_pk[7][2];
    signal input pk_index; // 0..6
    signal input query_s;
    signal input query_r[2];
   // Credential Signature
    signal input cred_type_id;
    signal input cred_pk[2]; // Public
    signal input cred_hashes[2]; // [claims_hash, associated_data_hash]
    signal input cred_genesis_issued_at;
    signal input cred_expires_at;
    signal input cred_s;
    signal input cred_r[2];
    signal input current_time_stamp; // Public
    // Merkle proof
    signal input merkle_root; // Public
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input rp_id; // Public
    signal input action; // Public
    // Dlog Equality Proof
    signal input dlog_e;
    signal input dlog_s;
    signal input oprf_pk[2]; // Public
    signal input oprf_response_blinded[2];
    // Unblinded response
    signal input oprf_response[2];
    // Nonce and signal hash
    signal input signal_hash; // Public
    signal input nonce; // Public
    // Commitment to the id
    signal input id_commitment_r;
    signal output id_commitment; // Public
    // Nullifier computation
    signal output nullifier; // Public

    // Derive the query
    // The domain separator is in the capacity element b"World ID Query"
    var query_poseidon[4] = Poseidon2(4)([1773399373884719043551600379785849, mt_index, rp_id, action]);
    signal query <== query_poseidon[1];

    // 1-3. Show that the original query was computed correctly
    component oprf_query = OprfQueryInner(MAX_DEPTH);
    oprf_query.pk <== user_pk;
    oprf_query.pk_index <== pk_index;
    oprf_query.s <== query_s;
    oprf_query.r <== query_r;
    oprf_query.cred_type_id <== cred_type_id;
    oprf_query.cred_pk <== cred_pk;
    oprf_query.cred_hashes <== cred_hashes;
    oprf_query.cred_genesis_issued_at <== cred_genesis_issued_at;
    oprf_query.cred_expires_at <== cred_expires_at;
    oprf_query.cred_s <== cred_s;
    oprf_query.cred_r <== cred_r;
    oprf_query.current_time_stamp <== current_time_stamp;
    oprf_query.merkle_root <== merkle_root;
    oprf_query.depth <== depth;
    oprf_query.mt_index <== mt_index;
    oprf_query.siblings <== siblings;
    oprf_query.beta <== beta;
    oprf_query.query <== query;

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
    var DS_N = 1773399373884719043551596035141478; // b"World ID Proof"
    var poseidon_nullifier[4] = Poseidon2(4)([DS_N, query, oprf_response[0], oprf_response[1]]);
    nullifier <== poseidon_nullifier[1];

    // Produce the commitment to the id
    var DS_C = 5199521648757207593; // b"H(id, r)"
    var poseidon_comm[3] = Poseidon2(3)([DS_C, mt_index, id_commitment_r]);
    id_commitment <== poseidon_comm[1];

    // Dummy square to prevent tampering signal_hash.
    // Same as done in Semaphore
    signal signal_hash_squared <== signal_hash * signal_hash;
    // Same for the nonce
    signal nonce_squared <== nonce * nonce;
}

// component main {public [cred_pk, current_time_stamp, merkle_root, depth, rp_id, action, oprf_pk, signal_hash, nonce]} = OprfNullifier(30);
