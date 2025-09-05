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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let config = OprfClientConfig::parse();
    let mut rng = rand::thread_rng();

    let oprf_public_key = (Projective::generator() * ScalarField::from(42 * 3)).into_affine();
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
    let merkle_root = QueryProofInput::merkle_root(pk.pk.x, pk.pk.y, &siblings, mt_index);
    let signal_hash = BaseField::rand(&mut rng);

    oprf_client::oprf::<MAX_DEPTH, _>(
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
        &mut rng,
    )
    .await?;

    Ok(())
}
