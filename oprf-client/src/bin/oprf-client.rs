use std::{fs::File, sync::Arc};

use ark_ec::{AffineRepr as _, CurveGroup as _, PrimeGroup as _};
use ark_ff::{UniformRand, Zero};
use circom_types::{groth16::ZKey, traits::CheckElement};
use clap::Parser;
use eddsa_babyjubjub::EdDSAPrivateKey;
use oprf_client::{
    Affine, BaseField, MAX_PUBLIC_KEYS, NullifierArgs, Projective, ScalarField,
    config::OprfClientConfig,
};
use oprf_core::proof_input_gen::query::QueryProofInput;
use oprf_types::{KeyEpoch, MerkleEpoch, RpId};
use rand::Rng as _;

const MAX_DEPTH: usize = 30;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing();
    let config = OprfClientConfig::parse();
    let mut rng = rand::thread_rng();

    let degree = 1;
    let oprf_public_key = (Projective::generator() * ScalarField::from(42)).into_affine();
    let key_epoch = KeyEpoch::default();
    let sk = EdDSAPrivateKey::random(&mut rng);
    let rp_sk = EdDSAPrivateKey::random(&mut rng); // TODO remove, not known
    let mt_index = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
    let rp_id = RpId::new(0);
    let action = BaseField::rand(&mut rng);
    let siblings: [BaseField; MAX_DEPTH] = std::array::from_fn(|_| BaseField::rand(&mut rng));
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let pk = sk.public();
    let rp_pk = rp_sk.public();
    let mut pks = [[BaseField::zero(); 2]; MAX_PUBLIC_KEYS];
    for (i, pki) in pks.iter_mut().enumerate() {
        if i as u64 == pk_index {
            pki[0] = pk.pk.x;
            pki[1] = pk.pk.y;
        } else {
            let sk_i = ScalarField::rand(&mut rng);
            let pk_i = (Affine::generator() * sk_i).into_affine();
            pki[0] = pk_i.x;
            pki[1] = pk_i.y;
        }
    }
    let merkle_root = QueryProofInput::merkle_root_from_pks(&pks, &siblings, mt_index);
    let signal_hash = BaseField::rand(&mut rng);
    let merkle_epoch = MerkleEpoch::default();
    let nonce = BaseField::rand(&mut rng);
    let signature = rp_sk.sign(nonce);
    let id_commitment_r = BaseField::rand(&mut rng);
    let query_zkey = ZKey::from_reader(File::open(config.query_zkey_path)?, CheckElement::No)?;
    let (query_matrices, query_pk) = query_zkey.into();
    let nullifier_zkey =
        ZKey::from_reader(File::open(config.nullifier_zkey_path)?, CheckElement::No)?;
    let (nullifier_matrices, nullifier_pk) = nullifier_zkey.into();

    let (_proof, _nullifier) = oprf_client::nullifier(
        &config.services,
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
        },
        &mut rng,
    )
    .await?;

    Ok(())
}
