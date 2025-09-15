use ark_ec::AffineRepr;
use ark_ff::UniformRand;

fn main() {
    println!("generates a fresh babyjubjub key-pair");
    println!("this will not upload the key anywhere");
    println!("you still will need to publish the public key and store the private key");
    let private_key = ark_babyjubjub::Fr::rand(&mut rand::thread_rng());
    let public_key = ark_babyjubjub::EdwardsAffine::generator() * private_key;

    println!("> sk = {private_key}");
    println!("> pk = {public_key}");
}
