//! Configuration types and CLI/environment parsing for the OPRF service.
//!
//! This module centralizes all runtime configuration of an OPRF peer.
//! It defines:
//!
//! * [`Environment`] — the deployment environment (`prod` or `dev`) with a helper to assert dev-only code.
//! * [`OprfPeerConfig`] — the full configuration for an OPRF peer, parsed from command-line flags
//!   or environment variables using [`clap`].  
//!
//! By keeping all parameters here, startup code can simply call
//! `OprfPeerConfig::parse()` to get a ready-to-use config struct.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use alloy::primitives::Address;
use clap::{Parser, ValueEnum};
use secrecy::SecretString;

/// The environment the service is running in.
///
/// Main usage for the `Environment` is to call
/// [`Environment::assert_is_dev`]. Services that are intended
/// for `dev` only (like SC mock watcher, local secret-manager,...)
/// shall assert that they are called from the `dev` environment.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Environment {
    /// Production environment.
    Prod,
    /// Development environment.
    Dev,
}

impl Environment {
    /// Asserts that `Environment` is `dev`. Panics if not the case.
    pub fn assert_is_dev(&self) {
        assert!(matches!(self, Environment::Dev), "Is not dev environment")
    }
}

/// The configuration for the OPRF peer.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfPeerConfig {
    /// The environment of OPRF-service (either `prod` or `dev`).
    #[clap(long, env = "OPRF_SERVICE_ENVIRONMENT", default_value = "prod")]
    pub environment: Environment,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_SERVICE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// Max time a request is valid, after that it is automatically cancelled and will be cleaned up.
    #[clap(
        long,
        env = "OPRF_SERVICE_REQUEST_LIFETIME",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub request_lifetime: Duration,

    /// Cleanup interval for session store.
    ///
    /// This interval specifies the time for the cleanup task to check
    /// old sessions, not the validity of a session.
    #[clap(
        long,
        env = "OPRF_SERVICE_SESSION_CLEANUP_INTERVAL",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub session_cleanup_interval: Duration,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_SERVICE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// Path to the verification key used to verify the proof provided by the user during session initialization.
    #[clap(long, env = "OPRF_SERVICE_USER_PROOF_VERIFICATION_KEY_PATH")]
    pub user_verification_key_path: PathBuf,

    /// The Address of the RpRegistry contract.
    #[clap(long, env = "OPRF_SERVICE_RP_REGISTRY_CONTRACT")]
    pub rp_registry_contract: Address,

    /// The address of the AccountRegistry smart contract
    #[clap(long, env = "OPRF_SERVICE_ACCOUNT_REGISTRY_CONTRACT")]
    pub account_registry_contract: Address,

    /// The websocket rpc url of the chain
    #[clap(
        long,
        env = "OPRF_SERVICE_CHAIN_WS_RPC_URL",
        default_value = "ws://127.0.0.1:8545"
    )]
    pub chain_ws_rpc_url: SecretString,

    /// Prefix for secret name to store rp secrets in secret-manager.
    /// The implementation will call `format!("{rp_secret_id_prefix}/{rp_id}")`
    #[clap(
        long,
        env = "OPRF_SERVICE_RP_SECRET_ID_PREFIX",
        default_value = "oprf/rp"
    )]
    pub rp_secret_id_prefix: String,

    /// Secret Id of the wallet private key.
    #[clap(long, env = "OPRF_SERVICE_WALLET_PRIVATE_KEY_SECRET_ID")]
    pub wallet_private_key_secret_id: String,

    /// The maximum size of the merkle store.
    ///
    /// Will drop old merkle roots if this capacity is reached.
    #[clap(long, env = "OPRF_SERVICE_MERKLE_STORE_SIZE", default_value = "100")]
    pub max_merkle_store_size: usize,

    /// The maximum delta between the received current_time_stamp the service current_time_stamp
    #[clap(
        long,
        env = "OPRF_SERVICE_CURRENT_TIME_STAMP_MAX_DIFFERENCE",
        default_value = "5min",
        value_parser = humantime::parse_duration

    )]
    pub current_time_stamp_max_difference: Duration,

    /// Interval to cleanup the signature history
    #[clap(
        long,
        env = "OPRF_SERVICE_SIGNATURE_HISTORY_CLEANUP_INTERVAL",
        default_value = "10min",
        value_parser = humantime::parse_duration

    )]
    pub signature_history_cleanup_interval: Duration,

    /// The location of the zkey for the key-gen proof in round 2 of KeyGen
    #[clap(long, env = "OPRF_SERVICE_KEY_GEN_ZKEY")]
    pub key_gen_zkey_path: PathBuf,

    /// The location of the graph binary for the key-gen witness extension
    #[clap(long, env = "OPRF_SERVICE_KEY_GEN_GRAPH")]
    pub key_gen_witness_graph_path: PathBuf,
}
