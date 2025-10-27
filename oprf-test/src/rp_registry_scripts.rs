use std::{collections::HashMap, path::PathBuf, process::Command, str::FromStr as _};

use alloy::primitives::Address;
use oprf_service::rp_registry::Types;
use oprf_types::RpId;
use regex::Regex;

pub fn deploy_test_setup(
    rpc_url: &str,
    taceo_admin_address: &str,
    taceo_admin_private_key: &str,
    env: HashMap<&str, String>,
) -> Address {
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cmd = cmd
        .current_dir(dir.join("../contracts"))
        .env("TACEO_ADMIN_ADDRESS", taceo_admin_address)
        .env("NUM_PEERS", "3")
        .env("THRESHOLD", "2")
        .envs(env)
        .arg("script")
        .arg("script/test/TestSetup.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"RpRegistry deployed to:\s*(0x[0-9a-fA-F]{40})").unwrap();
    let addr = re
        .captures(&stdout)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect("failed to parse deployed address from script output");
    Address::from_str(&addr).expect("valid addr")
}

pub fn init_key_gen(
    rpc_url: &str,
    key_gen_contract: Address,
    ecdsa_key: Types::EcDsaPubkeyCompressed,
    taceo_admin_private_key: &str,
) -> eyre::Result<RpId> {
    let pk_x = ecdsa_key.x.to_string();
    let pk_y_parity = ecdsa_key.yParity.to_string();
    let mut cmd = Command::new("forge");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rp_id = rand::random::<u128>();
    tracing::debug!("init key gen with rp_id: {rp_id}");
    tracing::debug!("with rpc url: {rpc_url}");
    tracing::debug!("on contract: {key_gen_contract}");
    let cmd = cmd
        .current_dir(dir.join("../contracts/script/deploy/"))
        .env("RP_REGISTRY_ADDRESS", key_gen_contract.to_string())
        .env("SESSION_ID", rp_id.to_string())
        .env("ECDSA_X", pk_x)
        .env("ECDSA_Y_PARITY", pk_y_parity)
        .arg("script")
        .arg("InitKeyGen.s.sol")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("--private-key")
        .arg(taceo_admin_private_key);
    tracing::debug!("executing cmd: {:?}", cmd);
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(RpId::new(rp_id))
}
