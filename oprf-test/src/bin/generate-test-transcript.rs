use std::collections::HashMap;

use alloy::primitives::U256;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use itertools::Itertools as _;
use oprf_core::keygen::KeyGenPoly;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    // we need three private keys
    let private_key0 = ark_babyjubjub::Fr::rand(&mut rng);
    let private_key1 = ark_babyjubjub::Fr::rand(&mut rng);
    let private_key2 = ark_babyjubjub::Fr::rand(&mut rng);

    let generator = ark_babyjubjub::EdwardsAffine::generator();

    let public_key0 = ((generator) * private_key0).into_affine();
    let public_key1 = ((generator) * private_key1).into_affine();
    let public_key2 = ((generator) * private_key2).into_affine();

    let degree = 1_u16;

    let poly0 = KeyGenPoly::new(&mut rng, degree as usize);
    let poly1 = KeyGenPoly::new(&mut rng, degree as usize);
    let poly2 = KeyGenPoly::new(&mut rng, degree as usize);

    let _should_public_key = poly0.get_pk_share() + poly1.get_pk_share() + poly2.get_pk_share();

    let peer_keys_flattened = [public_key0, public_key1, public_key2]
        .into_iter()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect_vec();

    let coeffs0 = poly0
        .coeffs()
        .iter()
        .map(|coeff| coeff.into())
        .collect::<Vec<U256>>();

    let coeffs1 = poly1
        .coeffs()
        .iter()
        .map(|coeff| coeff.into())
        .collect::<Vec<U256>>();

    let coeffs2 = poly2
        .coeffs()
        .iter()
        .map(|coeff| coeff.into())
        .collect::<Vec<U256>>();

    let nonces0 = (0..3)
        .map(|_| ark_babyjubjub::Fq::rand(&mut rng))
        .collect_vec();
    let nonces1 = (0..3)
        .map(|_| ark_babyjubjub::Fq::rand(&mut rng))
        .collect_vec();
    let nonces2 = (0..3)
        .map(|_| ark_babyjubjub::Fq::rand(&mut rng))
        .collect_vec();

    let mut input0_json = HashMap::new();
    input0_json.insert("degree", vec![U256::from(degree)]);
    input0_json.insert("my_sk", vec![private_key0.into()]);
    input0_json.insert("pks", peer_keys_flattened.clone());
    input0_json.insert("poly", coeffs0);
    input0_json.insert("nonces", nonces0.iter().map(|n| n.into()).collect_vec());
    let circom_input0 = serde_json::to_string_pretty(&input0_json).expect("can serialize");

    let mut input1_json = HashMap::new();
    input1_json.insert("degree", vec![U256::from(degree)]);
    input1_json.insert("my_sk", vec![private_key1.into()]);
    input1_json.insert("pks", peer_keys_flattened.clone());
    input1_json.insert("poly", coeffs1);
    input1_json.insert("nonces", nonces1.iter().map(|n| n.into()).collect_vec());
    let circom_input1 = serde_json::to_string_pretty(&input1_json).expect("can serialize");

    let mut input2_json = HashMap::new();
    input2_json.insert("degree", vec![U256::from(degree)]);
    input2_json.insert("my_sk", vec![private_key2.into()]);
    input2_json.insert("pks", peer_keys_flattened.clone());
    input2_json.insert("poly", coeffs2);
    input2_json.insert("nonces", nonces2.iter().map(|n| n.into()).collect_vec());
    let circom_input2 = serde_json::to_string_pretty(&input2_json).expect("can serialize");

    let mut material: HashMap<_, Vec<U256>> = HashMap::new();
    material.insert("alice_pk", vec![private_key0.into()]);
    material.insert("bob_pk", vec![private_key1.into()]);
    material.insert("carol_pk", vec![private_key2.into()]);

    material.insert(
        "alice_pub_k",
        vec![public_key0.x.into(), public_key0.y.into()],
    );
    material.insert(
        "bob_pub_k",
        vec![public_key1.x.into(), public_key1.y.into()],
    );
    material.insert(
        "carol_pub_k",
        vec![public_key2.x.into(), public_key2.y.into()],
    );

    let keys = serde_json::to_string_pretty(&material).expect("works");

    let mut round1: HashMap<_, Vec<U256>> = HashMap::new();
    round1.insert(
        "alice_comm",
        vec![poly0.get_pk_share().x.into(), poly0.get_pk_share().y.into()],
    );
    round1.insert("alice_coeffs", vec![poly0.get_coeff_commitment().into()]);
    round1.insert(
        "bob_comm",
        vec![poly1.get_pk_share().x.into(), poly1.get_pk_share().y.into()],
    );
    round1.insert("bob_coeffs", vec![poly1.get_coeff_commitment().into()]);
    round1.insert(
        "carol_comm",
        vec![poly2.get_pk_share().x.into(), poly2.get_pk_share().y.into()],
    );
    round1.insert("carol_coeffs", vec![poly2.get_coeff_commitment().into()]);

    let round1 = serde_json::to_string_pretty(&round1).expect("works");

    std::fs::write("input0.json", circom_input0).expect("works");
    std::fs::write("input1.json", circom_input1).expect("works");
    std::fs::write("input2.json", circom_input2).expect("works");
    std::fs::write("keys.json", keys).expect("works");
    std::fs::write("round1.json", round1).expect("works");
}
