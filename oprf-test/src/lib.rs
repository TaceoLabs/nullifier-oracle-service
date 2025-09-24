use std::{fs::File, path::PathBuf, sync::Arc, time::Duration};

use ark_ec::{AffineRepr as _, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand as _, Zero};
use circom_types::{groth16::ZKey, traits::CheckElement};
use k256::ecdsa::{SigningKey, signature::SignerMut as _};
use oprf_client::{
    Affine, BaseField, EdDSAPrivateKey, MAX_DEPTH, MAX_PUBLIC_KEYS, NullifierArgs, ScalarField,
};
use oprf_core::proof_input_gen::query::QueryProofInput;
use oprf_service::config::{Environment, OprfPeerConfig};
use oprf_types::{MerkleEpoch, RpId, ShareEpoch, crypto::RpNullifierKey};
use rand::{CryptoRng, Rng};
use smart_contract_mock::config::SmartContractMockConfig;

async fn start_service(id: usize) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = OprfPeerConfig {
        environment: Environment::Dev,
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        input_max_body_limit: 32768,
        request_lifetime: Duration::from_secs(5 * 60),
        session_cleanup_interval: Duration::from_micros(10),
        max_concurrent_jobs: 100000,
        max_wait_time_shutdown: Duration::from_secs(10),
        session_store_mailbox: 4096,
        user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
        chain_url: "http://localhost:6789".to_string(),
        chain_check_interval: Duration::from_millis(100),
        chain_epoch_max_difference: 10,
        private_key_secret_id: format!("oprf/sk/n{id}"),
        dlog_share_secret_id_suffix: format!("oprf/share/n{id}"),
        max_merkle_store_size: 10,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = oprf_service::start(config, never).await;
        eprintln!("service failed to start: {res:?}");
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn start_smart_contract_mock() -> String {
    let url = "http://localhost:6789".to_string();
    let config = SmartContractMockConfig {
        bind_addr: "0.0.0.0:6789".parse().expect("can parse"),
        max_root_cache_size: 10,
        add_pk_interval: Duration::from_secs(30),
        init_rp_registry: 1,
        add_rp_interval: Duration::from_secs(30),
        seed: 42,
        oprf_services: 3,
        oprf_degree: 1,
        oprf_public_keys_secret_id: "oprf/sc/pubs".to_string(),
        merkle_depth: MAX_DEPTH,
    };
    let never = async { futures::future::pending::<()>().await };
    tokio::spawn(async move {
        let res = smart_contract_mock::start(config, never).await;
        eprintln!("smart contract mock failed to start: {res:?}");
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reqwest::get(url.clone() + "/health").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("can start");
    url
}

pub async fn start_services() -> [String; 3] {
    [
        start_service(0).await,
        start_service(1).await,
        start_service(2).await,
    ]
}

pub async fn register_rp(chain_url: &str) -> eyre::Result<(RpId, RpNullifierKey)> {
    let client = reqwest::Client::new();
    let rp_id = client
        .post(format!("{chain_url}/api/admin/register-new-rp"))
        .send()
        .await?
        .json::<RpId>()
        .await?;
    let rp_nullifier_key = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let res = client
                .get(format!("{chain_url}/api/rp/{}", rp_id.into_inner()))
                .send()
                .await
                .expect("smart contract is online");
            if res.status().is_success() {
                break res.json::<RpNullifierKey>().await.expect("can deserialize");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("can fetch");
    Ok((rp_id, rp_nullifier_key))
}

pub async fn nullifier_args<R: Rng + CryptoRng>(
    rp_id: RpId,
    rp_nullifier_key: RpNullifierKey,
    rng: &mut R,
) -> eyre::Result<NullifierArgs> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let degree = 1;
    let key_epoch = ShareEpoch::default();
    let sk = EdDSAPrivateKey::random(rng);
    let mut rp_signing_key = SigningKey::from(k256::SecretKey::new(k256::Scalar::ONE.into())); // TODO remove
    let mt_index = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
    let action = BaseField::rand(rng);
    let siblings: [BaseField; MAX_DEPTH] = std::array::from_fn(|_| BaseField::rand(rng));
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let pk = sk.public();
    let mut pks = [[BaseField::zero(); 2]; MAX_PUBLIC_KEYS];
    for (i, pki) in pks.iter_mut().enumerate() {
        if i as u64 == pk_index {
            pki[0] = pk.pk.x;
            pki[1] = pk.pk.y;
        } else {
            let sk_i = ScalarField::rand(rng);
            let pk_i = (Affine::generator() * sk_i).into_affine();
            pki[0] = pk_i.x;
            pki[1] = pk_i.y;
        }
    }
    let merkle_root = QueryProofInput::merkle_root_from_pks(&pks, &siblings, mt_index);
    let signal_hash = BaseField::rand(rng);
    let merkle_epoch = MerkleEpoch::default();
    let nonce = BaseField::rand(rng);
    let signature = rp_signing_key.sign(&nonce.into_bigint().to_bytes_le());
    let id_commitment_r = BaseField::rand(rng);
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
    let cred_type_id = BaseField::rand(rng);
    let cred_sk = EdDSAPrivateKey::random(rng);
    let cred_pk = cred_sk.public();
    let cred_hashes = [BaseField::rand(rng), BaseField::rand(rng)]; // In practice, these are 2 hashes
    let genesis_issued_at = BaseField::from(rng.r#gen::<u64>());
    let expired_at_u64 = rng.gen_range(1..=u64::MAX);
    let current_time_stamp = BaseField::from(rng.gen_range(0..expired_at_u64));
    let expired_at = BaseField::from(expired_at_u64);
    Ok(NullifierArgs {
        rp_nullifier_key: rp_nullifier_key.inner(),
        key_epoch,
        sk,
        pks,
        pk_index,
        merkle_root,
        mt_index,
        siblings,
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
    })
}
