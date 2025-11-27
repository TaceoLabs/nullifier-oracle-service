use std::time::Duration;

use alloy::node_bindings::Anvil;
use alloy::providers::{ProviderBuilder, WsConnect};
use ark_ff::UniformRand as _;

use eyre::Context as _;
use oprf_test::oprf_key_registry_scripts::{self};
use oprf_test::{OprfKeyRegistry, TACEO_ADMIN_ADDRESS, TACEO_ADMIN_PRIVATE_KEY, health_checks};
use oprf_types::ShareEpoch;
use oprf_types::crypto::OprfPublicKey;
use rand::Rng as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::file_serial]
async fn nullifier_e2e_test() -> eyre::Result<()> {
    let anvil = Anvil::new().spawn();
    let mut rng = rand::thread_rng();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &anvil.endpoint(),
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
    );

    println!("Starting OPRF nodes...");
    let oprf_services = oprf_test::start_nodes(
        &anvil.ws_endpoint(),
        oprf_test::create_secret_managers(),
        oprf_key_registry_contract,
    )
    .await;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    println!("Fetching OPRF public-key...");
    let ws = WsConnect::new(anvil.ws_endpoint());
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

    println!("Running OPRF client flow...");
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let mt_index = rng.gen_range(0..(1 << 30)) as u64;

    let _nullifier = oprf_client_example::nullifier(
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
    let anvil = Anvil::new().spawn();

    println!("Deploying OprfKeyRegistry contract...");
    let oprf_key_registry_contract = oprf_key_registry_scripts::deploy_test_setup(
        &anvil.endpoint(),
        &TACEO_ADMIN_ADDRESS.to_string(),
        TACEO_ADMIN_PRIVATE_KEY,
    );

    let secret_managers = oprf_test::create_secret_managers();
    println!("Starting OPRF nodes...");
    let oprf_services = oprf_test::start_nodes(
        &anvil.ws_endpoint(),
        secret_managers.clone(),
        oprf_key_registry_contract,
    )
    .await;

    let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
        &anvil.endpoint(),
        oprf_key_registry_contract,
        TACEO_ADMIN_PRIVATE_KEY,
    );
    println!("init key-gen with rp id: {oprf_key_id}");

    let ws = WsConnect::new(anvil.ws_endpoint());
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
        &anvil.endpoint(),
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
