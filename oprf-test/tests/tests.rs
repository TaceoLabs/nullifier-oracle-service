#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_nullifier() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let chain_url = oprf_test::start_smart_contract_mock().await;
    let oprf_services = oprf_test::start_services().await;
    let (rp_id, rp_nullifier_key) = oprf_test::register_rp(&chain_url).await?;
    let args = oprf_test::nullifier_args(rp_id, rp_nullifier_key, &mut rng).await?;
    // TODO find better way
    // wait for the oprf peers to get the dlog share
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let (_proof, _nullifier) = oprf_client::nullifier(&oprf_services, args, &mut rng).await?;
    Ok(())
}

// #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
// async fn test_smart_contract() -> eyre::Result<()> {
//     let smart_contract = oprf_test::start_smart_contract_mock().await;
//     let oprf_services = oprf_test::start_services().await;
//     let mut rng = rand::thread_rng();
//     let args = oprf_test::nullifier_args(&smart_contract, &mut rng).await?;
//     // TODO find better way
//     // wait for the oprf peers to get the dlog share
//     tokio::time::sleep(std::time::Duration::from_secs(3)).await;

//     // Load the secret manager. For now we only support AWS. Most likely we want to load from the SC and reconstruct the secrets, but let's see if we really need this or AWS is just fine.
//     let id = 0;
//     let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     let config = OprfPeerConfig {
//         environment: Environment::Dev,
//         bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
//         input_max_body_limit: 32768,
//         request_lifetime: Duration::from_secs(5 * 60),
//         session_cleanup_interval: Duration::from_micros(10),
//         max_concurrent_jobs: 100000,
//         max_wait_time_shutdown: Duration::from_secs(10),
//         session_store_mailbox: 4096,
//         user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
//         chain_url: "http://localhost:6789".to_string(),
//         chain_check_interval: Duration::from_millis(100),
//         chain_epoch_max_difference: 10,
//         private_key_secret_id: format!("oprf/sk/n{id}"),
//         dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
//     };
//     let secret_manager = Arc::new(AwsSecretManager::new(Arc::new(config)).await);

//     // TODO load all RP_ids from SC

//     let crypto_device = Arc::new(
//         CryptoDevice::init(secret_manager, vec![args.rp_id])
//             .await
//             .context("while initiating crypto-device")?,
//     );
//     dbg!(&crypto_device.shares.0.read().keys());
//     let share0 = crypto_device
//         .shares
//         .get(&NullifierShareIdentifier {
//             rp_id: args.rp_id,
//             key_epoch: ShareEpoch::default(),
//         })
//         .unwrap();
//     let id = 1;
//     let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     let config = OprfPeerConfig {
//         environment: Environment::Dev,
//         bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
//         input_max_body_limit: 32768,
//         request_lifetime: Duration::from_secs(5 * 60),
//         session_cleanup_interval: Duration::from_micros(10),
//         max_concurrent_jobs: 100000,
//         max_wait_time_shutdown: Duration::from_secs(10),
//         session_store_mailbox: 4096,
//         user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
//         chain_url: "http://localhost:6789".to_string(),
//         chain_check_interval: Duration::from_millis(100),
//         chain_epoch_max_difference: 10,
//         private_key_secret_id: format!("oprf/sk/n{id}"),
//         dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
//     };
//     let secret_manager = Arc::new(AwsSecretManager::new(Arc::new(config)).await);

//     // TODO load all RP_ids from SC

//     let crypto_device = Arc::new(
//         CryptoDevice::init(secret_manager, vec![args.rp_id])
//             .await
//             .context("while initiating crypto-device")?,
//     );
//     let share1 = crypto_device
//         .shares
//         .get(&NullifierShareIdentifier {
//             rp_id: args.rp_id,
//             key_epoch: ShareEpoch::default(),
//         })
//         .unwrap();
//     let id = 2;
//     let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     let config = OprfPeerConfig {
//         environment: Environment::Dev,
//         bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
//         input_max_body_limit: 32768,
//         request_lifetime: Duration::from_secs(5 * 60),
//         session_cleanup_interval: Duration::from_micros(10),
//         max_concurrent_jobs: 100000,
//         max_wait_time_shutdown: Duration::from_secs(10),
//         session_store_mailbox: 4096,
//         user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
//         chain_url: "http://localhost:6789".to_string(),
//         chain_check_interval: Duration::from_millis(100),
//         chain_epoch_max_difference: 10,
//         private_key_secret_id: format!("oprf/sk/n{id}"),
//         dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
//     };
//     let secret_manager = Arc::new(AwsSecretManager::new(Arc::new(config)).await);

//     // TODO load all RP_ids from SC

//     let crypto_device = Arc::new(
//         CryptoDevice::init(secret_manager, vec![args.rp_id])
//             .await
//             .context("while initiating crypto-device")?,
//     );
//     let share2 = crypto_device
//         .shares
//         .get(&NullifierShareIdentifier {
//             rp_id: args.rp_id,
//             key_epoch: ShareEpoch::default(),
//         })
//         .unwrap();

//     dbg!([share0, share1, share2]);
//     let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 3, 2]);
//     let secret_key =
//         oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(&[share0, share1, share2], &lagrange);

//     let public_key_ = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

//     assert_eq!(public_key_, args.rp_nullifier_key);
//     Ok(())
// }
