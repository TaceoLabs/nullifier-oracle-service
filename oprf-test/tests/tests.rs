use std::str::FromStr;
use std::time::SystemTime;
use std::{path::PathBuf, time::Instant};

use alloy::network::EthereumWallet;
use alloy::{node_bindings::Anvil, signers::local::PrivateKeySigner};
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};

use groth16::Groth16;
use oprf_client::{MerkleMembership, NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_test::{
    credentials,
    key_gen_sc_mock::{self, DEFAULT_KEY_GEN_CONTRACT_ADDRESS, KeyGenProxy},
    world_id_protocol_mock::{
        self, ACCOUNT_REGISTRY_TREE_DEPTH, AuthTreeIndexer, DEFAULT_ACCOUNT_REGISTRY_ADDRESS,
    },
};
use oprf_types::ShareEpoch;

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

pub(crate) const PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    println!("==== OPRF Client Example ====");

    println!("Starting anvil...");
    let anvil = Anvil::new().spawn();

    println!("Deploying AccountRegistry contract...");
    world_id_protocol_mock::deploy_account_registry(&anvil.endpoint());

    println!("Deploying KeyGen contract...");
    key_gen_sc_mock::deploy_key_gen_contract(&anvil.endpoint());

    println!("Starting AuthTreeIndexer...");
    let mut auth_tree_indexer = AuthTreeIndexer::init(
        ACCOUNT_REGISTRY_TREE_DEPTH,
        DEFAULT_ACCOUNT_REGISTRY_ADDRESS,
        &anvil.ws_endpoint(),
    )
    .await?;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_services(&anvil.ws_endpoint()).await;

    tracing::info!("connecting to ETH wallet..");

    let private_key = PrivateKeySigner::from_str(PRIVATE_KEY)?;
    let wallet = EthereumWallet::from(private_key);

    tracing::info!("init key gen..");
    let mut key_gen_contract = KeyGenProxy::connect(
        &anvil.ws_endpoint(),
        DEFAULT_KEY_GEN_CONTRACT_ADDRESS,
        wallet,
    )
    .await?;
    let (rp_id, rp_nullifier_key) = key_gen_contract.init_key_gen().await?;

    println!("Creating account...");
    let key_material = world_id_protocol_mock::fetch_key_material()?;
    world_id_protocol_mock::create_account(&anvil.endpoint());

    println!("Get InclusionProof for account...");
    let account_index = auth_tree_indexer.account_idx().await;
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
        .as_millis() as u64;

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = key_gen_contract
        .sign(rp_id, &msg)
        .ok_or_else(|| eyre::eyre!("unknown rp id {rp_id}"))?;

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
