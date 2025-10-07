pub fn main(
    // signature verification of the oprf nonce
    pks: [[Field; 2]; 7],
    pk_index: Field,
    s: Field,
    r: [Field; 2],
    // credential signature parts
    cred_type_id: pub Field, // public
    cred_pk: [Field; 2],
    cred_hashes: [Field; 2],
    cred_genesis_issued_at: u64,
    cred_expires_at: u64,
    cred_s: Field,
    cred_r: [Field; 2],
    current_timestamp: pub u64, //public
    // Merkle tree parts
    merkle_root: Field,
    depth: pub u32, //public
    mt_index: Field,
    siblings: [Field; 10],
    // oprf query
    beta: Field,
    rp_id: pub Field, // public
    action: pub Field, // public
    nonce: Field,
) -> pub [Field; 2] {

    oprf_query::oprf_query::<10>(
        pks,
        pk_index,
        s,
        r,
        cred_type_id,
        cred_pk,
        cred_hashes,
        cred_genesis_issued_at,
        cred_expires_at,
        cred_s,
        cred_r,
        current_timestamp,
        merkle_root,
        depth,
        mt_index,
        siblings,
        beta,
        rp_id,
        action,
        nonce,
    )

}
