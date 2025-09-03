use std::fs::File;

use ark_ec::{AffineRepr as _, CurveGroup as _, PrimeGroup as _};
use ark_ff::{UniformRand, Zero};
use clap::Parser;
use eddsa_babyjubjub::EdDSAPrivateKey;
use oprf_client::{
    Affine, BaseField, MAX_PUBLIC_KEYS, Projective, ScalarField, config::OprfClientConfig,
};
use oprf_core::proof_input_gen::query::QueryProofInput;
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
    let sk = EdDSAPrivateKey::random(&mut rng);
    let mt_index = rng.gen_range(0..(1 << MAX_DEPTH)) as u64;
    let rp_id = BaseField::rand(&mut rng);
    let action = BaseField::rand(&mut rng);
    let siblings: [BaseField; MAX_DEPTH] = std::array::from_fn(|_| BaseField::rand(&mut rng));
    let pk_index = rng.gen_range(0..MAX_PUBLIC_KEYS) as u64;
    let pk = sk.public();
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
    let merkle_root = QueryProofInput::merkle_root(&pks, &siblings, mt_index);
    let signal_hash = BaseField::rand(&mut rng);
    let (query_pk, query_matrices) =
        ark_circom::read_zkey(&mut File::open(config.query_zkey_path)?)?;
    let (nullifier_pk, nullifier_matrices) =
        ark_circom::read_zkey(&mut File::open(config.nullifier_zkey_path)?)?;

    let (proof, nullifier) = oprf_client::nullifier(
        &config.services,
        oprf_public_key,
        sk,
        pks,
        pk_index,
        merkle_root,
        mt_index,
        siblings,
        rp_id,
        action,
        signal_hash,
        degree,
        &query_pk,
        &query_matrices,
        &nullifier_pk,
        &nullifier_matrices,
        &mut rng,
    )
    .await?;

    Ok(())
}
