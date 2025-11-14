use std::collections::HashMap;

use ruint::aliases::U256;

pub trait ProofInput {
    fn prepare_input(&self) -> HashMap<String, Vec<U256>>;
}
#[inline(always)]
pub fn fq_to_u256_vec(f: ark_babyjubjub::Fq) -> Vec<U256> {
    vec![f.into()]
}

#[inline(always)]
pub fn fq_seq_to_u256_vec(fs: &[ark_babyjubjub::Fq]) -> Vec<U256> {
    fs.iter().copied().flat_map(fq_to_u256_vec).collect()
}

#[inline(always)]
pub fn fr_to_u256_vec(f: ark_babyjubjub::Fr) -> Vec<U256> {
    vec![f.into()]
}

#[inline(always)]
pub fn affine_to_u256_vec(p: ark_babyjubjub::EdwardsAffine) -> Vec<U256> {
    vec![p.x.into(), p.y.into()]
}

#[inline(always)]
pub fn affine_seq_to_u256_vec(ps: &[ark_babyjubjub::EdwardsAffine]) -> Vec<U256> {
    ps.iter().copied().flat_map(affine_to_u256_vec).collect()
}
