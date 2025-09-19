pragma circom 2.2.2;

include "oprf_query.circom";

// Checks outside of the ZK proof: The output point q needs to be a valid BabyJubJub point in the correct subgroup.

template OprfRpIdQuery(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input pk[7][2];
    signal input pk_index; // 0..6
    signal input s;
    signal input r[2];
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
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    // Nonce
    signal input nonce; // Public
    signal output q[2]; // Public

    component inner = OprfQueryInner(MAX_DEPTH);
    inner.pk <== pk;
    inner.pk_index <== pk_index;
    inner.s <== s;
    inner.r <== r;
    inner.cred_type_id <== cred_type_id;
    inner.cred_pk <== cred_pk;
    inner.cred_hashes <== cred_hashes;
    inner.cred_genesis_issued_at <== cred_genesis_issued_at;
    inner.cred_expires_at <== cred_expires_at;
    inner.cred_s <== cred_s;
    inner.cred_r <== cred_r;
    inner.current_time_stamp <== current_time_stamp;
    inner.merkle_root <== merkle_root;
    inner.mt_index <== mt_index;
    inner.siblings <== siblings;
    inner.beta <== beta;
    inner.query <== mt_index;
    q <== inner.q;

    // Dummy square to prevent tampering nonce.
    // Same as done in Semaphore
    signal nonce_squared <== nonce * nonce;
}

// component main {public [cred_pk, current_time_stamp, merkle_root, nonce]} = OprfRpIdQuery(30);
