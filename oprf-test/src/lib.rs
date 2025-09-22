use std::{fs::File, path::PathBuf, sync::Arc, time::Duration};

use ark_ec::{AffineRepr as _, CurveGroup, PrimeGroup as _};
use ark_ff::{UniformRand as _, Zero};
use circom_types::{groth16::ZKey, traits::CheckElement};
use oprf_client::{
    Affine, BaseField, EdDSAPrivateKey, MAX_DEPTH, MAX_PUBLIC_KEYS, NullifierArgs, Projective,
    ScalarField,
};
use oprf_core::proof_input_gen::query::QueryProofInput;
use oprf_service::config::{Enviroment, OprfConfig};
use oprf_types::{KeyEpoch, MerkleEpoch, RpId};
use rand::{CryptoRng, Rng};

async fn start_service(id: usize) -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let url = format!("http://localhost:1{id:04}"); // set port based on id, e.g. 10001 for id 1
    let config = OprfConfig {
        environment: Enviroment::Dev,
        bind_addr: format!("0.0.0.0:1{id:04}").parse().unwrap(),
        input_max_body_limit: 32768,
        request_lifetime: Duration::from_secs(5 * 60),
        session_cleanup_interval: Duration::from_micros(10),
        max_concurrent_jobs: 100000,
        max_wait_time_shutdown: Duration::from_secs(10),
        session_store_mailbox: 4096,
        user_verification_key_path: dir.join("../circom/main/OPRFQueryProof.vk.json"),
        chain_url: "foo".to_string(),
        chain_check_interval: Duration::from_secs(60),
        chain_epoch_max_difference: 10,
        private_key_secret_id: "orpf/sk".to_string(),
        private_key_share_path: dir.join(format!("../data/pk{id}")),
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

pub async fn start_services() -> [String; 3] {
    [
        start_service(0).await,
        start_service(1).await,
        start_service(2).await,
    ]
}

pub fn nullifier_args<R: Rng + CryptoRng>(rng: &mut R) -> NullifierArgs {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let degree = 1;
    let oprf_public_key = (Projective::generator() * ScalarField::from(42)).into_affine();
    let key_epoch = KeyEpoch::default();
    let sk = EdDSAPrivateKey::random(rng);
    let rp_sk = EdDSAPrivateKey::random(rng); // TODO remove, not known
    let mt_index = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
    let rp_id = RpId::new(0);
    let action = BaseField::rand(rng);
    let siblings: [BaseField; MAX_DEPTH] = std::array::from_fn(|_| BaseField::rand(rng));
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let pk = sk.public();
    let rp_pk = rp_sk.public();
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
    let merkle_root = QueryProofInput::merkle_root(&pks, &siblings, mt_index);
    let signal_hash = BaseField::rand(rng);
    let merkle_epoch = MerkleEpoch::default();
    let nonce = BaseField::rand(rng);
    let signature = rp_sk.sign(nonce);
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
    NullifierArgs {
        oprf_public_key,
        key_epoch,
        sk,
        pks,
        pk_index,
        merkle_root,
        mt_index,
        siblings,
        rp_id,
        rp_pk,
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
    }
}
