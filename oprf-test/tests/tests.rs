use std::{path::PathBuf, time::Instant};

use ark_ff::UniformRand as _;

use groth16::Groth16;
use oprf_client::{NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_test::{credentials, sc_mock};
use oprf_types::{RpId, ShareEpoch, sc_mock::SignNonceResponse};
use rand::Rng;

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    println!("==== OPRF-client example ====");

    println!("starting Smart Contract mock...");
    let chain_url = sc_mock::start_smart_contract_mock().await;
    println!("starting OPRF-peers...");

    let oprf_services = oprf_test::start_services().await;
    println!("creating a new Rp Nullifier key..");

    let (rp_id, rp_nullifier_key) = sc_mock::register_rp(&chain_url).await?;

    println!("creating dummy user credentials..");
    let mut rng = rand::thread_rng();
    let key_material = credentials::random_user_keys(&mut rng);

    println!("registering at Smart Contract mock...");
    let merkle_membership =
        sc_mock::register_public_key(&chain_url, &key_material.pk_batch).await?;

    println!("create nonce and let the mock sign the nonce..");
    println!();
    println!("In a real world scenario, this signing the nonce is done by the RP,");
    println!("but for simplicity we let the Smart Contract mock sign it");
    println!();
    println!("IMPORTANT: The signature is computed as enc(nonce)|enc(timestamp)",);
    println!("where enc(x) is the little-endian bytes representation of x ");
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);

    // move signature to query
    let SignNonceResponse {
        signature,
        current_time_stamp,
    } = oprf_test::sign_nonce(&chain_url, rp_id, nonce).await?;

    println!();
    println!("loading zkeys and matrices..");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;

    let nullifier_vk = groth16_material.nullifier_vk();

    println!("generate a random query..");
    let query = random_query(rp_id, nonce, current_time_stamp, signature, &mut rng);

    println!("create a random credential signature..");

    let credential_signature = credentials::random_credential_signature(
        merkle_membership.mt_index,
        current_time_stamp,
        &mut rng,
    );

    let signal_hash = ark_babyjubjub::Fq::rand(&mut rng);
    let id_commitment_r = ark_babyjubjub::Fq::rand(&mut rng);

    println!("lets go");
    let time = Instant::now();

    let args = NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        groth16_material,
        key_material,
        signal_hash,
        id_commitment_r,
        rp_nullifier_key,
    };

    let (proof, public, nullifier) =
        oprf_client::nullifier(oprf_services.as_slice(), args, &mut rng).await?;
    let elapsed = time.elapsed();

    println!("checking proof...");

    Groth16::verify(&nullifier_vk, &proof.clone().into(), &public).expect("verifies");

    println!("success - took {:?}", elapsed);

    println!("produced nullifier: {nullifier}");

    Ok(())
}

fn random_query<R: Rng>(
    rp_id: RpId,
    nonce: ark_babyjubjub::Fq,
    current_time_stamp: u64,
    nonce_signature: k256::ecdsa::Signature,
    rng: &mut R,
) -> OprfQuery {
    OprfQuery {
        rp_id,
        share_epoch: ShareEpoch::default(),
        action: ark_babyjubjub::Fq::rand(rng),
        nonce,
        current_time_stamp,
        nonce_signature,
    }
}
