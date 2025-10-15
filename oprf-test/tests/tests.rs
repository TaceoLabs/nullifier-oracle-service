use std::time::{Duration, SystemTime};
use std::{path::PathBuf, time::Instant};

use alloy::node_bindings::Anvil;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::signers::k256;
use alloy::signers::k256::ecdsa::signature::Signer as _;
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};

use eyre::Context as _;
use groth16::Groth16;
use oprf_client::{MerkleMembership, NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_service::rp_registry::{KeyGen, Types};
use oprf_test::{TACEO_ADMIN_PRIVATE_KEY, init_rp_registry};
use oprf_test::{
    credentials,
    rp_registry_scripts::{self},
    world_id_protocol_mock::{self, ACCOUNT_REGISTRY_TREE_DEPTH, AuthTreeIndexer},
};
use oprf_types::ShareEpoch;
use oprf_types::crypto::RpNullifierKey;

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
    let account_registry_contract = world_id_protocol_mock::deploy_account_registry(
        &anvil.endpoint(),
        ACCOUNT_REGISTRY_TREE_DEPTH,
    );

    println!("Deploying KeyGen contract...");
    let key_gen_contract = init_rp_registry::start(&anvil.ws_endpoint(), "oprf/sk", true).await?;
    println!("deployed at address: {key_gen_contract}");

    println!("Starting AuthTreeIndexer...");
    let mut auth_tree_indexer = AuthTreeIndexer::init(
        ACCOUNT_REGISTRY_TREE_DEPTH,
        account_registry_contract,
        &anvil.ws_endpoint(),
    )
    .await?;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_services(
        &anvil.ws_endpoint(),
        key_gen_contract,
        account_registry_contract,
    )
    .await;

    let rp_signing_key = k256::SecretKey::random(&mut rand::thread_rng());
    let rp_pk = Types::EcDsaPubkeyCompressed::try_from(rp_signing_key.public_key())?;
    let rp_signing_key = k256::ecdsa::SigningKey::from(rp_signing_key);

    let rp_id = rp_registry_scripts::init_key_gen(
        &anvil.ws_endpoint(),
        key_gen_contract,
        rp_pk,
        TACEO_ADMIN_PRIVATE_KEY,
    )?;
    println!("init key-gen with rp id: {rp_id}");

    println!("Creating account...");
    let key_material = world_id_protocol_mock::fetch_key_material()?;
    world_id_protocol_mock::create_account(
        &anvil.endpoint(),
        &account_registry_contract.to_string(),
    );

    println!("Get InclusionProof for account...");
    let account_index = auth_tree_indexer.account_idx().await?;
    let merkle_proof = auth_tree_indexer.get_proof(account_index).await?;
    let merkle_membership = MerkleMembership::from(merkle_proof);

    println!("Creating nonce and and sign it...");
    println!("In a real-world scenario, the RP would sign the nonce.");
    println!();
    println!("IMPORTANT: The signature is computed as enc(nonce) | enc(timestamp),");
    println!("where enc(x) is the little-endian byte representation of x.");
    let nonce = ark_babyjubjub::Fq::rand(&mut rand::thread_rng());
    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = rp_signing_key.sign(&msg);

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

    let ws = WsConnect::new(anvil.ws_endpoint()); // rpc-url of anvil
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = KeyGen::new(key_gen_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            interval.tick().await;
            let maybe_rp_nullifier_key =
                contract.getRpNullifierKey(rp_id.into_inner()).call().await;
            if let Ok(rp_nullifier_key) = maybe_rp_nullifier_key {
                return eyre::Ok(RpNullifierKey::new(rp_nullifier_key.try_into()?));
            }
        }
    })
    .await
    .context("could not finish key-gen in 5 seconds")?
    .context("while polling RP key")?;

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
