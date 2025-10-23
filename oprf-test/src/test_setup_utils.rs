//! This module provides functionality to generate and manage OPRF peer keys.
//! It includes methods to create keys, upload them to AWS Secrets Manager, and handle key overwriting scenarios.

use std::collections::HashMap;

use alloy::primitives::Address;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use itertools::Itertools as _;
use oprf_service::rp_registry::Types;
use oprf_types::crypto::PeerPublicKey;

use crate::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, TACEO_ADMIN_ADDRESS,
    TACEO_ADMIN_PRIVATE_KEY, rp_registry_scripts,
};

pub fn deploy_rp_registry(
    ws_rps_url: &str,
    peer_public_keys: Vec<PeerPublicKey>,
) -> eyre::Result<Address> {
    let elements = peer_public_keys
        .into_iter()
        .map(Types::BabyJubJubElement::from)
        .collect_vec();
    let mut call_sol = HashMap::new();
    call_sol.insert("ALICE_PK_X", elements[0].x.to_string());
    call_sol.insert("ALICE_PK_Y", elements[0].y.to_string());
    call_sol.insert("BOB_PK_X", elements[1].x.to_string());
    call_sol.insert("BOB_PK_Y", elements[1].y.to_string());
    call_sol.insert("CAROL_PK_X", elements[2].x.to_string());
    call_sol.insert("CAROL_PK_Y", elements[2].y.to_string());
    call_sol.insert("ALICE_ADDRESS", OPRF_PEER_ADDRESS_0.to_string());
    call_sol.insert("BOB_ADDRESS", OPRF_PEER_ADDRESS_1.to_string());
    call_sol.insert("CAROL_ADDRESS", OPRF_PEER_ADDRESS_2.to_string());
    let key_gen_contract = rp_registry_scripts::deploy_test_setup(
        ws_rps_url,
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
        call_sol,
    );
    Ok(key_gen_contract)
}

pub fn generate_keys(amount_parties: usize) -> (Vec<PeerPublicKey>, Vec<ark_babyjubjub::Fr>) {
    let mut public_keys = Vec::with_capacity(amount_parties);
    let mut private_keys = Vec::with_capacity(amount_parties);
    for _ in 0..amount_parties {
        let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());
        let public_key = PeerPublicKey::from(
            (ark_babyjubjub::EdwardsAffine::generator() * private_key).into_affine(),
        );
        private_keys.push(private_key);
        public_keys.push(public_key);
    }

    (public_keys, private_keys)
}
