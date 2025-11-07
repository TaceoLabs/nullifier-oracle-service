//! Tests for Distributed Secret Generation
//!
//! This module contains integration tests for the [`DLogSecretGenService`],
//! verifying the correctness of the multi-round secret generation protocol
//! including proof generation and verification.

use std::path::PathBuf;

use ark_ec::{CurveGroup as _, PrimeGroup};
use itertools::Itertools;
use oprf_types::crypto::{PeerPublicKey, PeerPublicKeyList, RpSecretGenCiphertexts};
use rand::Rng;

use super::*;

async fn dlog_secret_gen(key_gen_material: Groth16Material) -> eyre::Result<DLogSecretGenService> {
    let rp_material = RpMaterialStore::new(HashMap::new());
    let dlog_secret_gen = DLogSecretGenService::init(rp_material, key_gen_material);
    Ok(dlog_secret_gen)
}

fn build_public_inputs(
    degree: u16,
    pk: PeerPublicKey,
    contribution: &RpSecretGenCiphertexts,
    peer_keys_flattened: &[ark_bn254::Fr],
    commitments: RpSecretGenCommitment,
) -> Vec<ark_babyjubjub::Fq> {
    // public input is:
    // 1) PublicKey from sender (Affine Point Babyjubjub)
    // 2) Commitment to share (Affine Point Babyjubjub)
    // 3) Commitment to coeffs (Basefield Babyjubjub)
    // 4) Ciphertexts for peers (in this case 3 Basefield BabyJubJub)
    // 5) Commitments to plaintexts (in this case 3 Affine Points BabyJubJub)
    // 6) Degree (Basefield BabyJubJub)
    // 7) Public Keys from peers (in this case 3 Affine Points BabyJubJub)
    // 8) Nonces (in this case 3 Basefield BabyJubJub)
    let mut ciphers = Vec::with_capacity(3);
    let mut comm_ciphers = Vec::with_capacity(3);
    let mut nonces = Vec::with_capacity(3);
    for cipher in contribution.ciphers.iter() {
        ciphers.push(cipher.cipher);
        comm_ciphers.push(cipher.commitment.x);
        comm_ciphers.push(cipher.commitment.y);
        nonces.push(cipher.nonce);
    }
    let mut public_inputs = Vec::with_capacity(24);
    public_inputs.push(pk.inner().x);
    public_inputs.push(pk.inner().y);
    public_inputs.push(commitments.comm_share.x);
    public_inputs.push(commitments.comm_share.y);
    public_inputs.push(commitments.comm_coeffs);
    public_inputs.extend(ciphers);
    public_inputs.extend(comm_ciphers);
    public_inputs.push(ark_babyjubjub::Fq::from(degree));
    public_inputs.extend(peer_keys_flattened.iter());
    public_inputs.extend(nonces);
    public_inputs
}

#[tokio::test]
async fn test_secret_gen() -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let rp_id = RpId::new(rng.r#gen());
    let threshold = 2;
    let graph = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("../circom/main/key-gen/OPRFKeyGenGraph.13.bin");
    let graph = std::fs::read(graph)?;
    let key_gen_zkey = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("../circom/main/key-gen/OPRFKeyGen.13.zkey");
    let key_gen_zkey = std::fs::read(key_gen_zkey)?;
    let key_gen_material = Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?;

    let mut dlog_secret_gen0 =
        dlog_secret_gen(Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?).await?;
    let mut dlog_secret_gen1 =
        dlog_secret_gen(Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?).await?;
    let mut dlog_secret_gen2 =
        dlog_secret_gen(Groth16Material::from_bytes(&key_gen_zkey, None, &graph)?).await?;

    let dlog_secret_gen0_round1 = dlog_secret_gen0.round1(rp_id, threshold);
    let dlog_secret_gen1_round1 = dlog_secret_gen1.round1(rp_id, threshold);
    let dlog_secret_gen2_round1 = dlog_secret_gen2.round1(rp_id, threshold);

    let commitments0 = dlog_secret_gen0_round1.contribution.clone();
    let commitments1 = dlog_secret_gen1_round1.contribution.clone();
    let commitments2 = dlog_secret_gen2_round1.contribution.clone();

    let round1_contributions = [
        dlog_secret_gen0_round1.contribution.clone(),
        dlog_secret_gen1_round1.contribution.clone(),
        dlog_secret_gen2_round1.contribution.clone(),
    ];
    let should_public_key = round1_contributions.iter().fold(
        ark_babyjubjub::EdwardsAffine::zero(),
        |acc, contribution| (acc + contribution.comm_share).into_affine(),
    );

    let peers = PeerPublicKeyList::from(vec![
        dlog_secret_gen0_round1.contribution.eph_pub_key,
        dlog_secret_gen1_round1.contribution.eph_pub_key,
        dlog_secret_gen2_round1.contribution.eph_pub_key,
    ]);
    let peer_keys_flattened = peers
        .clone()
        .into_iter()
        .flat_map(|p| [p.inner().x, p.inner().y])
        .collect_vec();

    let dlog_secret_gen0_round2 = dlog_secret_gen0
        .round2(rp_id, peers.clone())
        .context("while doing round2")?;
    let dlog_secret_gen1_round2 = dlog_secret_gen1
        .round2(rp_id, peers.clone())
        .context("while doing round2")?;
    let dlog_secret_gen2_round2 = dlog_secret_gen2
        .round2(rp_id, peers.clone())
        .context("while doing round2")?;

    assert_eq!(dlog_secret_gen0_round2.rp_id, rp_id);
    assert_eq!(dlog_secret_gen1_round2.rp_id, rp_id);
    assert_eq!(dlog_secret_gen2_round2.rp_id, rp_id);
    let peer_keys = peers.clone().into_inner();
    // verify the proofs
    // build public inputs for proof0
    let public_inputs0 = build_public_inputs(
        threshold - 1,
        peer_keys[0],
        &dlog_secret_gen0_round2.contribution,
        &peer_keys_flattened,
        commitments0,
    );
    let public_inputs1 = build_public_inputs(
        threshold - 1,
        peer_keys[1],
        &dlog_secret_gen1_round2.contribution,
        &peer_keys_flattened,
        commitments1,
    );
    let public_inputs2 = build_public_inputs(
        threshold - 1,
        peer_keys[2],
        &dlog_secret_gen2_round2.contribution,
        &peer_keys_flattened,
        commitments2,
    );
    let proof0 = dlog_secret_gen0_round2.contribution.proof;
    let proof1 = dlog_secret_gen1_round2.contribution.proof;
    let proof2 = dlog_secret_gen2_round2.contribution.proof;
    key_gen_material.verify_proof(&proof0.into(), &public_inputs0)?;
    key_gen_material.verify_proof(&proof1.into(), &public_inputs1)?;
    key_gen_material.verify_proof(&proof2.into(), &public_inputs2)?;

    let ciphers = (0..3)
        .map(|i| {
            vec![
                dlog_secret_gen0_round2.contribution.ciphers[i].clone(),
                dlog_secret_gen1_round2.contribution.ciphers[i].clone(),
                dlog_secret_gen2_round2.contribution.ciphers[i].clone(),
            ]
        })
        .collect_vec();
    let [ciphers0, ciphers1, ciphers2] = ciphers.try_into().expect("len is 3");

    let dlog_secret_gen0_round3 = dlog_secret_gen0.round3(rp_id, ciphers0)?;
    let dlog_secret_gen1_round3 = dlog_secret_gen1.round3(rp_id, ciphers1)?;
    let dlog_secret_gen2_round3 = dlog_secret_gen2.round3(rp_id, ciphers2)?;
    assert_eq!(dlog_secret_gen0_round3.rp_id, rp_id);
    assert_eq!(dlog_secret_gen1_round3.rp_id, rp_id);
    assert_eq!(dlog_secret_gen2_round3.rp_id, rp_id);

    let share0 = dlog_secret_gen0
        .finished_shares
        .get(&rp_id)
        .expect("gen0 has no share")
        .clone();
    let share1 = dlog_secret_gen1
        .finished_shares
        .get(&rp_id)
        .expect("gen0 has no share")
        .clone();
    let share2 = dlog_secret_gen2
        .finished_shares
        .get(&rp_id)
        .expect("gen0 has no share")
        .clone();

    let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
    let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
        &[share0.into(), share1.into(), share2.into()],
        &lagrange,
    );

    let is_public_key = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

    assert_eq!(is_public_key, should_public_key);

    let rp_public_key = k256::SecretKey::random(&mut rng).public_key();
    // finalize round
    let finalize0 =
        dlog_secret_gen0.finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))?;
    let finalize1 =
        dlog_secret_gen1.finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))?;
    let finalize2 =
        dlog_secret_gen2.finalize(rp_id, rp_public_key, RpNullifierKey::from(is_public_key))?;
    assert_eq!(finalize0.rp_id, rp_id);
    assert_eq!(finalize1.rp_id, rp_id);
    assert_eq!(finalize2.rp_id, rp_id);
    assert_eq!(finalize0.public_key, rp_public_key);
    assert_eq!(finalize1.public_key, rp_public_key);
    assert_eq!(finalize2.public_key, rp_public_key);
    assert_eq!(finalize0.rp_nullifier_key, is_public_key.into());
    assert_eq!(finalize1.rp_nullifier_key, is_public_key.into());
    assert_eq!(finalize2.rp_nullifier_key, is_public_key.into());

    let lagrange = oprf_core::shamir::lagrange_from_coeff(&[1, 2, 3]);
    let secret_key = oprf_core::shamir::reconstruct::<ark_babyjubjub::Fr>(
        &[
            finalize0.share.into(),
            finalize1.share.into(),
            finalize2.share.into(),
        ],
        &lagrange,
    );

    let is_public_key = (ark_babyjubjub::EdwardsProjective::generator() * secret_key).into_affine();

    assert_eq!(is_public_key, should_public_key);
    // check that shares are removed correctly
    assert!(!dlog_secret_gen0.finished_shares.contains_key(&rp_id));
    assert!(!dlog_secret_gen1.finished_shares.contains_key(&rp_id));
    assert!(!dlog_secret_gen2.finished_shares.contains_key(&rp_id));

    Ok(())
}
