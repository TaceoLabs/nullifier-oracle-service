pragma circom 2.2.2;

include "eddsa_poseidon2/eddsaposeidon2.circom";
include "poseidon2/poseidon2.circom";
include "merkle_tree/binary_merkle_root.circom";
include "encode_to_curve_babyjj/encode_to_curve_babyjj.circom";
include "babyjubjub/babyjubjub.circom";

// Checks outside of the ZK proof: The output point q needs to be a valid BabyJubJub point in the correct subgroup.

template OprfQueryInner(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input pk[2];
    signal input s;
    signal input r[2];
    // Merkle proof
    signal input merkle_root; // Public
    signal input index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input query;
    signal output q[2]; // Public

    // Ensure beta < Subgroup Order
    component beta_range_check = BabyJubJubIsInFr();
    beta_range_check.in <== beta;

    // 1. Verify sk/pk by verifying a signature to a known message
    component eddsa_verifier = EdDSAPoseidon2Verifier();
    eddsa_verifier.Ax <== pk[0];
    eddsa_verifier.Ay <== pk[1];
    eddsa_verifier.S <== s;
    eddsa_verifier.Rx <== r[0];
    eddsa_verifier.Ry <== r[1];
    eddsa_verifier.M <== query;

    // 2. Merkle proof of pk
    // Hash the pk to get a field element, which is the leaf
    var poseidon_result[3] = Poseidon2(3)([0, pk[0], pk[1]]);
    component merkle_proof = BinaryMerkleRoot(MAX_DEPTH);
    merkle_proof.leaf <== poseidon_result[1];
    merkle_proof.depth <== MAX_DEPTH;
    merkle_proof.index <== index;
    merkle_proof.siblings <== siblings;

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
}

template OprfQuery(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input pk[2];
    signal input s;
    signal input r[2];
    // Merkle proof
    signal input merkle_root; // Public
    signal input index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input rp_id; // Public
    signal input action; // Public
    signal output q[2]; // Public

    // Derive the query
    var query_poseidon[4] = Poseidon2(4)([0, index, rp_id, action]);
    signal query <== query_poseidon[1];

    component inner = OprfQueryInner(MAX_DEPTH);
    inner.pk <== pk;
    inner.s <== s;
    inner.r <== r;
    inner.merkle_root <== merkle_root;
    inner.index <== index;
    inner.siblings <== siblings;
    inner.beta <== beta;
    inner.query <== query;
    q <== inner.q;
}

// component main {public [merkle_root, rp_id, action]} = OprfQuery(30);
