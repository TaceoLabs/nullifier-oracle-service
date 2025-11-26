use std::str::FromStr as _;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use alloy::network::{EthereumWallet, TransactionBuilder as _};
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256;
use alloy::signers::k256::ecdsa::signature::Signer as _;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};

use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::Context as _;
use oprf_test::{
    MOCK_RP_SECRET_KEY, OPRF_PEER_ADDRESS_0, OprfKeyRegistry, TACEO_ADMIN_ADDRESS,
    TACEO_ADMIN_PRIVATE_KEY, anvil_testcontainer, health_checks, indexer_testcontainer,
    postgres_testcontainer,
};
use oprf_test::{
    credentials,
    oprf_key_registry_scripts::{self},
    world_id_protocol_mock::{self},
};
use oprf_types::ShareEpoch;
use oprf_types::crypto::OprfPublicKey;
use oprf_world_client::{NullifierArgs, OprfQuery, VerifiableNullifier};
use rand::Rng as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn world_nullifier_e2e_test() -> eyre::Result<()> {
    let (_anvil_container, host_rpc_url, host_ws_url, bridge_rpc_url, bridge_ws_url) =
        anvil_testcontainer().await?;
    let mut rng = rand::thread_rng();

    println!("Deploying AccountRegistry contract...");
    let account_registry_contract = world_id_protocol_mock::deploy_account_registry(&host_rpc_url);

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &host_ws_url,
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
    );

    println!("Starting indexer...");
    let (_postgres_container, db_url) = postgres_testcontainer().await?;
    let (_indexer_container, indexer_url) = indexer_testcontainer(
        &bridge_rpc_url,
        &bridge_ws_url,
        &account_registry_contract.to_string(),
        &db_url,
    )
    .await?;

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_world_services(
        &host_ws_url,
        oprf_test::create_secret_managers(),
        oprf_key_registry_contract,
        account_registry_contract,
    )
    .await;

    // let rp_pk = EcDsaPubkeyCompressed::try_from(MOCK_RP_SECRET_KEY.public_key())?;

    let private_key = PrivateKeySigner::from_str(TACEO_ADMIN_PRIVATE_KEY)
        .context("while reading wallet private key")?;
    let wallet = EthereumWallet::from(private_key);

    println!("Creating account...");
    let seed = rand::random::<[u8; 32]>();
    let onchain_signer = PrivateKeySigner::from_bytes(&seed.into())?;
    let offchain_signer_private_key = EdDSAPrivateKey::from_bytes(seed);

    let key_material = world_id_protocol_mock::create_account(
        offchain_signer_private_key,
        &onchain_signer,
        &host_ws_url,
        account_registry_contract,
        wallet.clone(),
    )
    .await?;
    // FIXME we need to wait for 5 seconds (unfortunately) because there is a bug in the world-indexer.
    // remove this as soon as the bug is resolved
    tokio::time::sleep(Duration::from_secs(5)).await;
    let merkle_membership = world_id_protocol_mock::fetch_inclusion_proof(
        &onchain_signer,
        &host_ws_url,
        account_registry_contract,
        wallet,
        &indexer_url,
        Duration::from_secs(10),
    )
    .await?;

    let current_time_stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_secs();
    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &host_ws_url,
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    println!("Creating nonce and and sign it...");
    println!("In a real-world scenario, the RP would sign the nonce.");
    println!();
    println!("IMPORTANT: The signature is computed as enc(nonce) | enc(timestamp),");
    println!("where enc(x) is the little-endian byte representation of x.");
    let nonce = ark_babyjubjub::Fq::rand(&mut rand::thread_rng());

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let signature = k256::ecdsa::SigningKey::from(MOCK_RP_SECRET_KEY.clone()).sign(&msg);

    println!();
    println!("Loading zkeys and matrices...");
    let query_material = oprf_world_client::load_embedded_query_material();
    let nullifier_material = oprf_world_client::load_embedded_nullifier_material();

    println!("Generating a random query...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let query = OprfQuery {
        oprf_key_id,
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
    let id_commitment_r = ark_babyjubjub::Fq::rand(&mut rng);

    println!("Fetching OPRF public-key...");
    let ws = WsConnect::new(&host_ws_url);
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = OprfKeyRegistry::new(oprf_key_registry_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    // very graceful timeout for CI
    let oprf_public_key = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            interval.tick().await;
            let maybe_oprf_public_key = contract
                .getOprfPublicKey(oprf_key_id.into_inner())
                .call()
                .await;
            if let Ok(oprf_public_key) = maybe_oprf_public_key {
                return eyre::Ok(OprfPublicKey::new(oprf_public_key.try_into()?));
            }
        }
    })
    .await
    .context("could not finish key-gen in 60 seconds")?
    .context("while polling RP key")?;

    // send a dummy tx to get enough blocks to reach the required 2 confirmations in key-gen
    let tx = TransactionRequest::default()
        .with_from(TACEO_ADMIN_ADDRESS)
        .with_to(OPRF_PEER_ADDRESS_0)
        .with_value(U256::from(1));
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    if !receipt.status() {
        eyre::bail!("failed to send dummy tx");
    }

    println!("Running OPRF client flow...");
    let args = NullifierArgs {
        credentials_signature: credential_signature.clone(),
        merkle_membership: merkle_membership.clone(),
        query,
        key_material,
        oprf_public_key,
        signal_hash,
        id_commitment_r,
    };

    let time = Instant::now();
    let VerifiableNullifier {
        proof,
        public_input,
        nullifier,
        id_commitment: _,
    } = oprf_world_client::nullifier(
        oprf_services.as_slice(),
        2,
        &query_material,
        &nullifier_material,
        args,
        &mut rng,
    )
    .await?;

    println!("Verifying proof...");
    nullifier_material
        .verify_proof(&proof.clone().into(), &public_input)
        .expect("verifies");

    let elapsed = time.elapsed();
    println!("Success! Completed in {elapsed:?}");
    println!("Produced nullifier: {nullifier}");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn example_nullifier_e2e_test() -> eyre::Result<()> {
    let (_anvil_container, _host_rpc_url, host_ws_url, _bridge_rpc_url, _bridge_ws_url) =
        anvil_testcontainer().await?;
    let mut rng = rand::thread_rng();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &host_ws_url,
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
    );

    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_example_services(
        &host_ws_url,
        oprf_test::create_secret_managers(),
        oprf_key_registry_contract,
    )
    .await;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &host_ws_url,
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    println!("Fetching OPRF public-key...");
    let ws = WsConnect::new(&host_ws_url);
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = OprfKeyRegistry::new(oprf_key_registry_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    // very graceful timeout for CI
    let oprf_public_key = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            interval.tick().await;
            let maybe_oprf_public_key = contract
                .getOprfPublicKey(oprf_key_id.into_inner())
                .call()
                .await;
            if let Ok(oprf_public_key) = maybe_oprf_public_key {
                return eyre::Ok(OprfPublicKey::new(oprf_public_key.try_into()?));
            }
        }
    })
    .await
    .context("could not finish key-gen in 60 seconds")?
    .context("while polling RP key")?;

    // send a dummy tx to get enough blocks to reach the required 2 confirmations in key-gen
    let tx = TransactionRequest::default()
        .with_from(TACEO_ADMIN_ADDRESS)
        .with_to(OPRF_PEER_ADDRESS_0)
        .with_value(U256::from(1));
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    if !receipt.status() {
        eyre::bail!("failed to send dummy tx");
    }

    println!("Running OPRF client flow...");

    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let mt_index = rng.gen_range(0..(1 << 30)) as u64;

    let _nullifier = oprf_example_client::nullifier(
        oprf_services.as_slice(),
        2,
        oprf_public_key,
        oprf_key_id,
        ShareEpoch::default(),
        action,
        mt_index,
        &mut rng,
    )
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn test_delete_oprf_key() -> eyre::Result<()> {
    let (_anvil_container, host_rpc_url, host_ws_url, _, _) = anvil_testcontainer().await?;

    println!("Deploying AccountRegistry contract...");
    let account_registry_contract = world_id_protocol_mock::deploy_account_registry(&host_rpc_url);

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &host_ws_url,
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
    );

    let secret_managers = oprf_test::create_secret_managers();
    println!("Starting OPRF peers...");
    let oprf_services = oprf_test::start_world_services(
        &host_ws_url,
        secret_managers.clone(),
        oprf_key_registry_contract,
        account_registry_contract,
    )
    .await;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &host_ws_url,
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    let ws = WsConnect::new(&host_ws_url); // rpc-url of anvil
    let provider = ProviderBuilder::new()
        .connect_ws(ws)
        .await
        .context("while connecting to RPC")?;
    let contract = OprfKeyRegistry::new(oprf_key_registry_contract, provider.clone());
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    // very graceful timeout for CI
    let should_oprf_public_key = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            interval.tick().await;
            let maybe_oprf_public_key = contract
                .getOprfPublicKey(oprf_key_id.into_inner())
                .call()
                .await;
            if let Ok(oprf_public_key) = maybe_oprf_public_key {
                return eyre::Ok(OprfPublicKey::new(oprf_public_key.try_into()?));
            }
        }
    })
    .await
    .context("could not finish key-gen in 60 seconds")?
    .context("while polling RP key")?;

    // send a dummy tx to get enough blocks to reach the required 2 confirmations in key-gen
    let tx = TransactionRequest::default()
        .with_from(TACEO_ADMIN_ADDRESS)
        .with_to(OPRF_PEER_ADDRESS_0)
        .with_value(U256::from(1));
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    if !receipt.status() {
        eyre::bail!("failed to send dummy tx");
    }

    println!("checking that key-material is registered at services..");
    let is_oprf_public_key = health_checks::oprf_public_key_from_services(
        oprf_key_id,
        &oprf_services,
        Duration::from_secs(5),
    )
    .await
    .context("while loading OPRF key-material from services")?;
    assert_eq!(is_oprf_public_key, should_oprf_public_key);

    let secret_before_delete0 = secret_managers[0].load_rps();
    let secret_before_delete1 = secret_managers[1].load_rps();
    let secret_before_delete2 = secret_managers[2].load_rps();
    let should_rps = vec![oprf_key_id];
    assert_eq!(secret_before_delete0, should_rps);
    assert_eq!(secret_before_delete1, should_rps);
    assert_eq!(secret_before_delete2, should_rps);

    println!("deletion of OPRF key-material..");
    oprf_key_registry_scripts::delete_oprf_key_material(
        &host_ws_url,
        oprf_key_registry_contract,
        oprf_key_id,
        TACEO_ADMIN_PRIVATE_KEY,
    );

    println!("check that services don't know key anymore...");
    health_checks::assert_rp_unknown(oprf_key_id, &oprf_services, Duration::from_secs(5)).await?;
    println!("check that shares are not in localstack anymore...");

    let secrets_after_delete0 = secret_managers[0].load_rps();
    let secrets_after_delete1 = secret_managers[1].load_rps();
    let secrets_after_delete2 = secret_managers[2].load_rps();

    assert!(secrets_after_delete0.is_empty());
    assert!(secrets_after_delete1.is_empty());
    assert!(secrets_after_delete2.is_empty());

    Ok(())
}
