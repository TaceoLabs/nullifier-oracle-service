pragma circom 2.0.0;

include "keygen.circom";

// Checks outside of the ZK proof: The public keys pks need to be valid BabyJubJub points in the correct subgroup.

template KeyGenSingleParty(MAX_DEGREE, INDEX) {
    // The actual degree
    signal input degree; // Public
    // My secret key and public key
    signal input my_sk;
    signal output my_pk[2]; // Public
    // All parties' public keys
    signal input pk[2]; // Public
    // Coefficients of the sharing polynomial
    signal input poly[MAX_DEGREE + 1];
    // Nonces used in the encryption of the shares
    signal input nonce; // Public
    // Commitments to the poly
    signal output comm_input_share[2]; // Public
    signal output comm_coeffs; // Public
    // Outputs are the ciphertext and the commitment to the share
    signal output ciphertext; // Public
    signal output comm_share[2]; // Public

    // Check that the coefficients beyond 'degree' are zero
    CheckDegree(MAX_DEGREE)(degree, poly);

    ////////////////////////////////////////////////////////////////////////////
    // Commit to the polynomial and my public key
    ////////////////////////////////////////////////////////////////////////////

    component keygen_commit = KeyGenCommit(MAX_DEGREE);
    keygen_commit.my_sk <== my_sk;
    keygen_commit.poly <== poly;
    my_pk <== keygen_commit.my_pk;
    comm_input_share <== keygen_commit.comm_input_share;
    comm_coeffs <== keygen_commit.comm_coeffs;

    ////////////////////////////////////////////////////////////////////////////
    // Derive and encrypt the share
    ////////////////////////////////////////////////////////////////////////////

    var share = EvalPolyModP(MAX_DEGREE, INDEX + 1)(keygen_commit.poly_checked);

    component derive_encrypt = EncryptAndCommit();
    derive_encrypt.my_sk <== keygen_commit.sk_checked;
    derive_encrypt.share <== share;
    derive_encrypt.pk <== pk;
    derive_encrypt.nonce <== nonce;
    ciphertext <== derive_encrypt.ciphertext;
    comm_share <== derive_encrypt.comm_share;
}

template KeyGenSinglePartyVar(MAX_DEGREE, MAX_INDEX_BITS) {
    // The actual degree
    signal input degree; // Public
    // The index of the party who is receiving the share
    signal input party_index; // Public
    // My secret key and public key
    signal input my_sk;
    signal output my_pk[2]; // Public
    // All parties' public keys
    signal input pk[2]; // Public
    // Coefficients of the sharing polynomial
    signal input poly[MAX_DEGREE + 1];
    // Nonces used in the encryption of the shares
    signal input nonce; // Public
    // Commitments to the poly
    signal output comm_input_share[2]; // Public
    signal output comm_coeffs; // Public
    // Outputs are the ciphertext and the commitment to the share
    signal output ciphertext; // Public
    signal output comm_share[2]; // Public

    // Check that the coefficients beyond 'degree' are zero
    CheckDegree(MAX_DEGREE)(degree, poly);

    ////////////////////////////////////////////////////////////////////////////
    // Commit to the polynomial and my public key
    ////////////////////////////////////////////////////////////////////////////

    component keygen_commit = KeyGenCommit(MAX_DEGREE);
    keygen_commit.my_sk <== my_sk;
    keygen_commit.poly <== poly;
    my_pk <== keygen_commit.my_pk;
    comm_input_share <== keygen_commit.comm_input_share;
    comm_coeffs <== keygen_commit.comm_coeffs;

    ////////////////////////////////////////////////////////////////////////////
    // Derive and encrypt the share
    ////////////////////////////////////////////////////////////////////////////

    var share = EvalPolyModPVar(MAX_DEGREE, MAX_INDEX_BITS)(keygen_commit.poly_checked, party_index+1);

    component derive_encrypt = EncryptAndCommit();
    derive_encrypt.my_sk <== keygen_commit.sk_checked;
    derive_encrypt.share <== share;
    derive_encrypt.pk <== pk;
    derive_encrypt.nonce <== nonce;
    ciphertext <== derive_encrypt.ciphertext;
    comm_share <== derive_encrypt.comm_share;
}

// component main {public [degree, pk, nonce]} = KeyGenSingleParty(1, 2);
// component main {public [degree, pk, nonce]} = KeyGenSingleParty(15, 29);

// component main {public [degree, party_index, pk, nonce]} = KeyGenSinglePartyVar(1, 7);
// component main {public [degree, party_index, pk, nonce]} = KeyGenSinglePartyVar(15, 7);
