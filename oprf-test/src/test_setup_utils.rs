//! This module provides functionality to generate and manage OPRF peer keys.
//! It includes methods to create keys, upload them to AWS Secrets Manager, and handle key overwriting scenarios.

use std::collections::HashMap;

use alloy::primitives::Address;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::UniformRand as _;
use aws_sdk_secretsmanager::operation::create_secret::CreateSecretError;
use itertools::Itertools as _;
use oprf_service::rp_registry::Types;
use oprf_types::crypto::PeerPublicKey;

use crate::{
    OPRF_PEER_ADDRESS_0, OPRF_PEER_ADDRESS_1, OPRF_PEER_ADDRESS_2, TACEO_ADMIN_ADDRESS,
    TACEO_ADMIN_PRIVATE_KEY, rp_registry_scripts,
};

pub async fn deploy_and_keygen(
    ws_rps_url: &str,
    private_key_secret_id_prefix: &str,
    overwrite_old_keys: bool,
) -> eyre::Result<Address> {
    let peer_public_keys =
        generate_keys(3, private_key_secret_id_prefix, overwrite_old_keys).await?;
    deploy_rp_registry(ws_rps_url, peer_public_keys)
}

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

/// Generate and upload OPRF keys ot AWS secrets-manger
pub async fn generate_keys(
    amount_parties: usize,
    private_key_secret_id_prefix: &str,
    overwrite_old_keys: bool,
) -> eyre::Result<Vec<PeerPublicKey>> {
    tracing::info!("generating private keys for {amount_parties} services");
    tracing::debug!("prefix: {private_key_secret_id_prefix}");
    tracing::debug!("overwrite: {overwrite_old_keys}");
    let client = aws_sdk_secretsmanager::Client::new(&aws_config::load_from_env().await);

    let mut public_keys = Vec::with_capacity(amount_parties);
    for i in 0..amount_parties {
        let secret_id = format!("{private_key_secret_id_prefix}/n{i}");
        let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());
        upload_to_aws(
            &client,
            secret_id,
            private_key.to_string(),
            overwrite_old_keys,
        )
        .await?;
        public_keys.push(PeerPublicKey::from(
            (ark_babyjubjub::EdwardsAffine::generator() * private_key).into_affine(),
        ));
    }

    Ok(public_keys)
}

async fn upload_to_aws(
    client: &aws_sdk_secretsmanager::Client,
    secret_id: String,
    message: String,
    overwrite_old_keys: bool,
) -> eyre::Result<()> {
    // If we don't allow overwrite we simply create the secret and propagate any errors
    if !overwrite_old_keys {
        tracing::debug!("creating secret: {secret_id}");
        client
            .create_secret()
            .name(secret_id)
            .secret_string(message)
            .send()
            .await?;
    } else {
        tracing::debug!("creating secret: {secret_id}");
        // Try to create first, if it exists then add a new version
        match client
            .create_secret()
            .name(secret_id.clone())
            .secret_string(message.clone())
            .send()
            .await
        {
            Ok(_) => (),
            Err(e) => match e.into_service_error() {
                CreateSecretError::ResourceExistsException(_) => {
                    // Resource exist so do put
                    tracing::debug!("already exists - overwrite");
                    client
                        .put_secret_value()
                        .secret_id(secret_id)
                        .secret_string(message)
                        .send()
                        .await?;
                }
                x => Err(x)?,
            },
        }
    }
    Ok(())
}
