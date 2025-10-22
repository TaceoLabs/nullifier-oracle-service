use std::str::FromStr as _;
use std::time::{Duration, SystemTime};
use std::{path::PathBuf, time::Instant};

use alloy::network::EthereumWallet;
use alloy::node_bindings::Anvil;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::signers::k256;
use alloy::signers::k256::ecdsa::signature::Signer as _;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};

use eyre::Context as _;
use groth16::Groth16;
use oprf_client::{MerkleMembership, NullifierArgs, OprfQuery, zk::Groth16Material};
use oprf_service::rp_registry::CredentialSchemaIssuerRegistry::Pubkey;
use oprf_service::rp_registry::{RpRegistry, Types};
use oprf_test::world_id_protocol_mock::Authenticator;
use oprf_test::{MOCK_RP_SECRET_KEY, TACEO_ADMIN_PRIVATE_KEY, test_setup_utils};
use oprf_test::{
    credentials,
    rp_registry_scripts::{self},
    world_id_protocol_mock::{self, AuthTreeIndexer},
};
use oprf_types::ShareEpoch;
use oprf_types::crypto::RpNullifierKey;

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;
use rand::Rng;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    println!("==== OPRF Client Example ====");

    println!("Starting anvil...");
    let anvil = Anvil::new().spawn();

    println!("Deploying AccountRegistry contract...");
    let account_registry_contract =
        world_id_protocol_mock::deploy_account_registry(&anvil.endpoint());

    println!("Deploying RpRegistry contract...");
    let rp_registry_contract =
        test_setup_utils::deploy_and_keygen(&anvil.ws_endpoint(), "oprf/sk", true).await?;

    println!("Starting AuthTreeIndexer...");
    let auth_tree_indexer =
        AuthTreeIndexer::init(account_registry_contract, &anvil.ws_endpoint()).await?;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_services(
        &anvil.ws_endpoint(),
        rp_registry_contract,
        account_registry_contract,
    )
    .await;

    let rp_pk = Types::EcDsaPubkeyCompressed::try_from(MOCK_RP_SECRET_KEY.public_key())?;
    let rp_id = rp_registry_scripts::init_key_gen(
        &anvil.ws_endpoint(),
        rp_registry_contract,
        rp_pk,
        TACEO_ADMIN_PRIVATE_KEY,
    )?;
    println!("init key-gen with rp id: {rp_id}");

    println!("Creating account...");
    let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)
        .context("while reading wallet private key")?;
    let wallet = EthereumWallet::from(private_key);
    let mut authenticator = Authenticator::new(
        &rng.r#gen::<[u8; 32]>(),
        &anvil.ws_endpoint(),
        account_registry_contract,
        wallet,
    )
    .await?;
    let key_material = authenticator.create_account().await?;
    let account_index = authenticator.account_index().await?;

    println!("Get InclusionProof for account...");
    let merkle_proof = auth_tree_indexer
        .get_proof(account_index.try_into().unwrap())
        .await?;
    let merkle_membership = MerkleMembership::try_from(merkle_proof)?;

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
    let signature = k256::ecdsa::SigningKey::from(MOCK_RP_SECRET_KEY.clone()).sign(&msg);

    println!();
    println!("Loading zkeys and matrices...");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let groth16_material = Groth16Material::new(
        dir.join("../circom/main/OPRFQueryProof.zkey"),
        dir.join("../circom/main/OPRFNullifierProof.zkey"),
    )?;
    let nullifier_vk = groth16_material.nullifier_vk();

    println!("Generating a random query...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let query = OprfQuery {
        rp_id,
        share_epoch: ShareEpoch::default(),
        action,
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

    println!("Fetching RpNullifierKey...");
    let ws = WsConnect::new(anvil.ws_endpoint()); // rpc-url of anvil
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = RpRegistry::new(rp_registry_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(5), async {
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

    println!("Running OPRF client flow...");
    let args = NullifierArgs {
        credential_signature: credential_signature.clone(),
        merkle_membership: merkle_membership.clone(),
        query,
        groth16_material,
        key_material,
        signal_hash,
        rp_nullifier_key,
    };

    let time = Instant::now();
    let (proof, public, nullifier, id_commitment) =
        oprf_client::nullifier(oprf_services.as_slice(), 2, args, &mut rng).await?;

    println!("Verifying proof...");
    Groth16::verify(&nullifier_vk, &proof.clone().into(), &public).expect("verifies");

    println!("Verifying proof on chain...");
    let cred_pk = Pubkey {
        x: credential_signature.issuer.pk.x.into(),
        y: credential_signature.issuer.pk.y.into(),
    };

    let proof = Types::Groth16Proof::from(proof);
    let result = contract
        .verifyNullifierProof(
            nullifier.into(),
            action.into(),
            rp_id.into_inner(),
            id_commitment.into(),
            nonce.into(),
            signal_hash.into(),
            merkle_membership.root.into_inner().into(),
            current_time_stamp.try_into().unwrap(),
            cred_pk,
            proof,
        )
        .call()
        .await?;
    assert!(result, "on-chain verification failed");

    let elapsed = time.elapsed();
    println!("Success! Completed in {:?}", elapsed);
    println!("Produced nullifier: {nullifier}");
    Ok(())
}
