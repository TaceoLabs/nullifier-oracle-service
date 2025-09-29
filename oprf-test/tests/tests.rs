use std::{fs::File, path::PathBuf, sync::Arc};

use ark_ff::UniformRand as _;
use circom_types::{groth16::ZKey, traits::CheckElement};
use oprf_client::{BaseField, EdDSAPrivateKey, MAX_PUBLIC_KEYS, NullifierArgs};
use oprf_types::{
    ShareEpoch,
    sc_mock::{SignNonceResponse, UserPublicKey},
};
use rand::Rng as _;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("oprf_client=debug"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
async fn test_nullifier() -> eyre::Result<()> {
    install_tracing();
    let mut rng = rand::thread_rng();
    let chain_url = oprf_test::start_smart_contract_mock().await;
    let oprf_services = oprf_test::start_services().await;
    let (rp_id, rp_nullifier_key) = oprf_test::register_rp(&chain_url).await?;
    let sk = EdDSAPrivateKey::random(&mut rng);
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let mut public_key = UserPublicKey::random(&mut rng);
    public_key.values[pk_index as usize] = sk.public().pk;
    let (merkle_epoch, merkle_path) =
        oprf_test::register_public_key(&chain_url, public_key.clone()).await?;

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let degree = 1;
    let share_epoch = ShareEpoch::default();
    let action = BaseField::rand(&mut rng);
    let signal_hash = BaseField::rand(&mut rng);
    let nonce = BaseField::rand(&mut rng);
    let SignNonceResponse {
        signature,
        current_time_stamp,
    } = oprf_test::sign_nonce(&chain_url, rp_id, nonce).await?;
    let id_commitment_r = BaseField::rand(&mut rng);
    let query_zkey = ZKey::from_reader(
        File::open(dir.join("../circom/main/OPRFQueryProof.zkey")).expect("can open"),
        CheckElement::No,
    )
    .expect("valid zkey");
    let (query_matrices, query_pk) = query_zkey.into();
    let nullifier_zkey = ZKey::from_reader(
        File::open(dir.join("../circom/main/OPRFNullifierProof.zkey")).expect("can open"),
        CheckElement::No,
    )
    .expect("valid zkey");
    let (nullifier_matrices, nullifier_pk) = nullifier_zkey.into();
    let cred_type_id = BaseField::rand(&mut rng);
    let cred_sk = EdDSAPrivateKey::random(&mut rng);
    let cred_pk = cred_sk.public();
    let cred_hashes = [BaseField::rand(&mut rng), BaseField::rand(&mut rng)]; // In practice, these are 2 hashes
    let genesis_issued_at = BaseField::from(rng.r#gen::<u64>());
    let expired_at_u64 = rng.gen_range(1..=u64::MAX);
    let expired_at = BaseField::from(expired_at_u64);
    let args = NullifierArgs {
        rp_nullifier_key: rp_nullifier_key.inner(),
        share_epoch,
        sk,
        pks: public_key
            .values
            .iter()
            .map(|p| [p.x, p.y])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        pk_index,
        merkle_root: merkle_path.root.into_inner(),
        mt_index: merkle_path.index,
        siblings: merkle_path.siblings.try_into().unwrap(),
        rp_id,
        action,
        signal_hash,
        merkle_epoch,
        nonce,
        signature,
        id_commitment_r,
        degree,
        query_pk: Arc::new(query_pk),
        query_matrices: Arc::new(query_matrices),
        nullifier_pk: Arc::new(nullifier_pk),
        nullifier_matrices: Arc::new(nullifier_matrices),
        cred_type_id,
        cred_pk,
        cred_sk,
        cred_hashes,
        genesis_issued_at,
        expired_at,
        current_time_stamp,
    };

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
