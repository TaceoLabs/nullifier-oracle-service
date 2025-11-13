pragma circom 2.2.2;

include "eddsa_poseidon2/eddsaposeidon2.circom";
include "poseidon2/poseidon2.circom";
include "merkle_tree/binary_merkle_root.circom";
include "encode_to_curve_babyjj/encode_to_curve_babyjj.circom";
include "babyjubjub/babyjubjub.circom";

// Checks outside of the ZK proof: The output point q needs to be a valid BabyJubJub point in the correct subgroup.

// The MerkleTree has 7 public keys at its leaf. We need to hash them to proof membership
template MerkleLeaf() {
    signal input pk[7][2];
    signal output out;

    component hasher = Poseidon2(16);
    hasher.in[0] <== 105702839725298824521994315; // Domain separator in capacity element b"World ID PK"
    for (var i = 0; i < 7; i++) {
        hasher.in[i * 2 + 1] <== pk[i][0];
        hasher.in[i * 2 + 2] <== pk[i][1];
    }
    hasher.in[15] <== 0;
    out <== hasher.out[1];
}

// Chooses a public key from the list of NUM_KEYS public keys based on the index. If the index is out of range, the result is zero. There is no check enforcing this zero, since in this use case it is checked later on anyway.
template ChoosePublicKey(NUM_KEYS) {
    signal input pk[NUM_KEYS][2];
    signal input index; // 0..NUM_KEYS-1
    signal output out[2];

    // We compare the index with each possible value 0..NUM_KEYS-1.
    // Thus the result is a vector of 0 and 1, with at most one 1 (else all 0).
    // The finally chosen public key can then be computed with a simple dot product, where the output is 0 if all are 0.

    // Comparators
    component cmp[NUM_KEYS];
    for (var i = 0; i < NUM_KEYS; i++) {
        cmp[i] = IsEqual();
        cmp[i].in[0] <== index;
        cmp[i].in[1] <== i;
    }

    // Dot product
    signal dots[NUM_KEYS][2];
    dots[0][0] <== cmp[0].out * pk[0][0]; // Initialize with 0 or the first public key
    dots[0][1] <== cmp[0].out * pk[0][1]; // Initialize with 0 or the first public key
    for (var i = 1; i < NUM_KEYS; i++) {
        dots[i][0] <== dots[i - 1][0] + cmp[i].out * pk[i][0];
        dots[i][1] <== dots[i - 1][1] + cmp[i].out * pk[i][1];
    }

    // Resulting public key is not checked to be non-zero here, it is checked in the EdDSA verifier later on. Both checks (BabyJubJubCheck and is_zero() on the x coordinate) in EdDSAPoseidon2Verifier() trigger a failure in case the output is zero.
    out[0] <== dots[NUM_KEYS-1][0];
    out[1] <== dots[NUM_KEYS-1][1];
}

// In the CheckCredentialSignature template, we need to recompute a hash and verify the signature of this hash. Furthermore, we need to check whether the credential is still valid (i.e., not expired) by proving the current_time_stamp is less than expires_at. We note that genesis_issued_at is just there to recompute the hash and we do not check anything about it (e.g., whether it is in the past).
template CheckCredentialSignature() {
    // Signature
    signal input s;
    signal input r[2];
    // Public key
    signal input pk[2];
    // Credential data
    signal input credential_type_id;
    signal input user_id;
    signal input genesis_issued_at;
    signal input expires_at;
    signal input hashes[2]; // [claims_hash, associated_data_hash]
    // Current time
    signal input current_time_stamp;

    // Calculate the message hash
    component hash = Poseidon2(8);
    hash.in[0] <== 1790969822004668215611014194230797064349043274; // Domain separator in capacity element b"POSEIDON2+EDDSA-BJJ"
    hash.in[1] <== credential_type_id;
    hash.in[2] <== user_id;
    hash.in[3] <== genesis_issued_at;
    hash.in[4] <== expires_at;
    hash.in[5] <== hashes[0];
    hash.in[6] <== hashes[1];
    hash.in[7] <== 0;

    // Verify the signature
    component eddsa_verifier = EdDSAPoseidon2Verifier();
    eddsa_verifier.Ax <== pk[0];
    eddsa_verifier.Ay <== pk[1];
    eddsa_verifier.S <== s;
    eddsa_verifier.Rx <== r[0];
    eddsa_verifier.Ry <== r[1];
    eddsa_verifier.M <== hash.out[1];

    // Range check the 3 timestamps
    // We think these two checks are not really necessary since it would produce an invalid signature if they were out of range (and the signer should have checked it), but it does not add many constraints....
    var genesis_in_range[64] = Num2Bits(64)(genesis_issued_at);
    var expires_in_range[64] = Num2Bits(64)(expires_at);
    // var current_in_range[64] = Num2Bits(64)(current_time_stamp); // Should be checked outside of the ZK proof

    // Check the credential is currently valid
    var lt = LessThan(64)([current_time_stamp, expires_at]);
    lt === 1;
}


template OprfQueryInner(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk corresponding to pk is never used in a proof directly)
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
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input query;
    signal output q[2]; // Public

    // Ensure beta < Subgroup Order
    component beta_range_check = BabyJubJubIsInFr();
    beta_range_check.in <== beta;

    // 1. Verify sk/pk by verifying a signature to a known message
    signal chosen_pk[2] <== ChoosePublicKey(7)(pk, pk_index);
    component eddsa_verifier = EdDSAPoseidon2Verifier();
    eddsa_verifier.Ax <== chosen_pk[0];
    eddsa_verifier.Ay <== chosen_pk[1];
    eddsa_verifier.S <== s;
    eddsa_verifier.Rx <== r[0];
    eddsa_verifier.Ry <== r[1];
    eddsa_verifier.M <== query;

    // 2. Merkle proof of pk
    // Hash the pk to get a field element, which is the leaf
    signal merkle_leaf <== MerkleLeaf()(pk);
    // Actual MerkleProof
    component merkle_proof = BinaryMerkleRoot(MAX_DEPTH);
    merkle_proof.leaf <== merkle_leaf;
    merkle_proof.depth <== depth;
    merkle_proof.index <== mt_index;
    merkle_proof.siblings <== siblings;
    merkle_proof.out === merkle_root;

    // 3. Query is computed correctly
    component hasher = EncodeToCurveBabyJubJub();
    hasher.in <== query;
    BabyJubJubPoint() { twisted_edwards } p;
    p.x <== hasher.out[0];
    p.y <== hasher.out[1];

    component multiplier = BabyJubJubScalarMul();
    multiplier.p <== p;
    multiplier.e <== beta_range_check.out;
    q[0] <== multiplier.out.x;
    q[1] <== multiplier.out.y;

    // 4. Credential signature is valid
    component cred_sig_checker = CheckCredentialSignature();
    cred_sig_checker.s <== cred_s;
    cred_sig_checker.r <== cred_r;
    cred_sig_checker.pk <== cred_pk;
    cred_sig_checker.credential_type_id <== cred_type_id;
    cred_sig_checker.user_id <== mt_index;
    cred_sig_checker.genesis_issued_at <== cred_genesis_issued_at;
    cred_sig_checker.expires_at <== cred_expires_at;
    cred_sig_checker.hashes <== cred_hashes;
    cred_sig_checker.current_time_stamp <== current_time_stamp;
}

template OprfQuery(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk corresponding to pk is never used in a proof directly)
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
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input rp_id; // Public
    signal input action; // Public
    // Nonce
    signal input nonce; // Public
    signal output q[2]; // Public

    // Derive the query
    // The domain separator is in the capacity element b"World ID Query"
    var query_poseidon[4] = Poseidon2(4)([1773399373884719043551600379785849, mt_index, rp_id, action]);
    signal query <== query_poseidon[1];

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
    inner.depth <== depth;
    inner.mt_index <== mt_index;
    inner.siblings <== siblings;
    inner.beta <== beta;
    inner.query <== query;
    q <== inner.q;

    // Dummy square to prevent tampering nonce.
    // Same as done in Semaphore
    signal nonce_squared <== nonce * nonce;
}

// component main {public [cred_pk, current_time_stamp, merkle_root, depth, rp_id, action, nonce]} = OprfQuery(30);
