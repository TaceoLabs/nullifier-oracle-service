use std::{path::PathBuf, time::Instant};

use alloy::node_bindings::Anvil;
use ark_ff::{PrimeField as _, UniformRand as _};

use groth16::Groth16;
use oprf_client::{MAX_DEPTH, MerkleMembership, NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_test::{
    credentials, sc_mock,
    world_id_protocol_mock::{
        self, ACCOUNT_REGISTRY, ACCOUNT_REGISTRY_TREE_DEPTH, AuthTreeIndexer,
    },
};
use oprf_types::{MerkleEpoch, ShareEpoch, sc_mock::SignNonceResponse};

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    println!("==== OPRF Client Example ====");

    println!("Starting anvil...");
    let anvil = Anvil::new().spawn();

    println!("Deploying AccountRegistry contract...");
    world_id_protocol_mock::deploy_account_registry(&anvil.endpoint());

    println!("Starting AuthTreeIndexer...");
    let mut auth_tree_indexer = AuthTreeIndexer::init(
        ACCOUNT_REGISTRY_TREE_DEPTH,
        ACCOUNT_REGISTRY,
        &anvil.ws_endpoint(),
    )
    .await?;

    println!("Starting Smart Contract mock...");
    let chain_url = sc_mock::start_smart_contract_mock().await;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_services(&anvil.ws_endpoint()).await;

    println!("Creating a new RP nullifier key...");
    let (rp_id, rp_nullifier_key) = sc_mock::register_rp(&chain_url).await?;

    println!("Creating account...");
    let key_material = world_id_protocol_mock::fetch_key_material()?;
    world_id_protocol_mock::create_account(&anvil.endpoint());

    println!("Get InclusionProof for account...");
    let account_index = auth_tree_indexer.account_idx().await;
    let merkle_proof = auth_tree_indexer.get_proof(account_index).await?;
    // TODO cleanup conversion of merkle_proof/merkle_membership
    let depth = merkle_proof.proof.len() as u64;
    let mut siblings = merkle_proof
        .proof
        .into_iter()
        .map(|p| ark_babyjubjub::Fq::from_be_bytes_mod_order(&p.to_be_bytes::<32>()))
        .collect::<Vec<_>>();
    // pad sibling to max depth
    for _ in 0..MAX_DEPTH as u64 - depth {
        siblings.push(ark_babyjubjub::Fq::default());
    }
    let merkle_membership = MerkleMembership {
        epoch: MerkleEpoch::default(),
        root: merkle_proof.root.into(),
        depth, // send actual depth of contract merkle tree
        mt_index: merkle_proof.leaf_index,
        siblings: siblings.try_into().unwrap(),
    };

    println!("Creating nonce and letting the mock sign it...");
    println!();
    println!("In a real-world scenario, the RP would sign the nonce.");
    println!("For simplicity, we let the Smart Contract mock do it here.");
    println!();
    println!("IMPORTANT: The signature is computed as enc(nonce) | enc(timestamp),");
    println!("where enc(x) is the little-endian byte representation of x.");
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);

    let SignNonceResponse {
        signature,
        current_time_stamp,
    } = sc_mock::sign_nonce(&chain_url, rp_id, nonce).await?;

    println!();
    println!("Loading zkeys and matrices...");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;
    let nullifier_vk = groth16_material.nullifier_vk();

    println!("Generating a random query...");
    let query = OprfQuery {
        rp_id,
        share_epoch: ShareEpoch::default(),
        action: ark_babyjubjub::Fq::rand(&mut rng),
        nonce,
        current_time_stamp,
        nonce_signature: signature,
    };

    println!("Creating a random credential signature...");
    let credential_signature = credentials::random_credential_signature(
        merkle_membership.mt_index,
        current_time_stamp,
        &mut rng,
    );

    let signal_hash = ark_babyjubjub::Fq::rand(&mut rng);

    println!("Running OPRF client flow...");
    let time = Instant::now();

    let args = NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        groth16_material,
        key_material,
        signal_hash,
        rp_nullifier_key,
    };

    let (proof, public, nullifier) =
        oprf_client::nullifier(oprf_services.as_slice(), 2, args, &mut rng).await?;
    let elapsed = time.elapsed();

    println!("Verifying proof...");
    Groth16::verify(&nullifier_vk, &proof.clone().into(), &public).expect("verifies");

    println!("Success! Completed in {:?}", elapsed);
    println!("Produced nullifier: {nullifier}");

    Ok(())
}
