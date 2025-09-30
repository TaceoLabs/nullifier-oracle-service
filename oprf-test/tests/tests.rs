use std::{path::PathBuf, time::Instant};

use ark_ff::UniformRand as _;

use groth16::Groth16;
use oprf_client::{NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_test::{credentials, sc_mock};
use oprf_types::{ShareEpoch, sc_mock::SignNonceResponse};

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    println!("==== OPRF Client Example ====");

    println!("Starting Smart Contract mock...");
    let chain_url = sc_mock::start_smart_contract_mock().await;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_services().await;

    println!("Creating a new RP nullifier key...");
    let (rp_id, rp_nullifier_key) = sc_mock::register_rp(&chain_url).await?;

    println!("Creating dummy user credentials...");
    let mut rng = rand::thread_rng();
    let key_material = credentials::random_user_keys(&mut rng);

    println!("Registering public key at Smart Contract mock...");
    let merkle_membership =
        sc_mock::register_public_key(&chain_url, &key_material.pk_batch).await?;

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
