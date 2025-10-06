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

    /// Max size we allow for uploading input for jobs in bytes.
    ///
    /// Default value = 32kB,
    #[clap(
        long,
        env = "OPRF_SERVICE_INPUT_MAX_BODY_LIMIT",
        default_value = "32768"
    )]
    pub input_max_body_limit: usize,

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

    /// Max concurrently allowed HTTP requests.
    #[clap(
        long,
        env = "OPRF_SERVICE_MAX_CONCURRENT_HTTP_REQUESTS",
        default_value = "100000"
    )]
    pub max_concurrent_jobs: usize,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_SERVICE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// Mailbox size for the session store.
    #[clap(
        long,
        env = "OPRF_SERVICE_SESSION_MAILBOX_SIZE",
        default_value = "4096"
    )]
    pub session_store_mailbox: usize,

    /// Path to the verification key used to verify the proof provided by the user during session initialization.
    #[clap(long, env = "OPRF_SERVICE_USER_PROOF_VERIFICATION_KEY_PATH")]
    pub user_verification_key_path: PathBuf,

    /// The Address of the KeyGen contract.
    #[clap(
        long,
        env = "OPRF_SERVICE_KEY_GEN_CONTRACT",
        default_value = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
    )]
    pub key_gen_contract: Address,

    /// The address of the AccountRegistry smart contract
    #[clap(
        long,
        env = "OPRF_SERVICE_ACCOUNT_REGISTRY_CONTRACT",
        default_value = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    )]
    pub account_registry_contract: Address,

    /// Wallet private key
    #[clap(long, env = "OPRF_SERVICE_WALLET_PRIVATE_KEY")]
    pub wallet_private_key: SecretString,

    /// The websocket rpc url of the chain
    #[clap(
        long,
        env = "OPRF_SERVICE_CHAIN_WS_RPC_URL",
        default_value = "ws://127.0.0.1:8545"
    )]
    pub chain_ws_rpc_url: String,

    /// Max epoch in the future.
    /// If an epoch is too far in the future, the service will not perform a manual check. This is defined by this value (no longer than this difference inclusive).
    #[clap(
        long,
        env = "OPRF_SERVICE_CHAIN_EPOCH_MAX_LOOK_AHEAD",
        default_value = "10"
    )]
    pub chain_epoch_max_difference: u128,

    /// The name/ARN of the service's private-key.
    #[clap(
        long,
        env = "OPRF_SERVICE_PRIVATE_KEY_SECRET_ID",
        default_value = "oprf/sk"
    )]
    pub private_key_secret_id: String,

    /// Suffix for secret name to store DLogShares in secret-manager.
    /// The implementation will call `format!("{dlog_share_secret_id_suffix}/{rp_id}")`
    #[clap(
        long,
        env = "OPRF_SERVICE_DLOG_SHARE_SECRET_ID_SUFFIX",
        default_value = "oprf/share/"
    )]
    pub dlog_share_secret_id_suffix: String,

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

    /// The max depth of the merkle tree
    #[clap(long, env = "OPRF_SERVICE_MAX_MERKLE_DEPTH", default_value = "30")]
    pub max_merkle_depth: u64,
}
