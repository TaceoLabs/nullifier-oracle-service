//! Configuration types and CLI/environment parsing for TACEO:Oprf.
//!
//! Concrete implementations may have a more detailed config and can use the exposed [`OprfNodeConfig`] and flatten it with `#[clap(flatten)]`.
//!
//! Additionally this module defines the [`Environment`] to assert dev-only code.

use std::{path::PathBuf, time::Duration};

use alloy::primitives::Address;
use clap::{Parser, ValueEnum};
use secrecy::SecretString;

/// The environment the service is running in.
///
/// Main usage for the `Environment` is to call
/// [`Environment::assert_is_dev`]. Services that are intended
/// for `dev` only (like local secret-manager,...)
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

/// The configuration for TACEO:Oprf core functionality.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfNodeConfig {
    /// The environment of OPRF-service (either `prod` or `dev`).
    #[clap(long, env = "OPRF_NODE_ENVIRONMENT", default_value = "prod")]
    pub environment: Environment,

    /// Max time a request is valid, after that it is automatically cancelled and will be cleaned up.
    #[clap(
        long,
        env = "OPRF_NODE_REQUEST_LIFETIME",
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
        env = "OPRF_NODE_SESSION_CLEANUP_INTERVAL",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub session_cleanup_interval: Duration,

    /// Max message size the websocket connection accepts.
    ///
    /// Default value: 8 kilobytes
    #[clap(long, env = "OPRF_SERVICE_MAX_MESSAGE_SIZE", default_value = "8192")]
    pub ws_max_message_size: usize,

    /// Max time a created session is valid.
    ///
    /// This interval specifies how long a websocket connection is kept alive after a user initiates a session.
    #[clap(
        long,
        env = "OPRF_SERVICE_SESSION_LIFETIME",
        default_value="5min",
        value_parser = humantime::parse_duration
    )]
    pub session_lifetime: Duration,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The websocket rpc url of the chain
    #[clap(
        long,
        env = "OPRF_NODE_CHAIN_WS_RPC_URL",
        default_value = "ws://127.0.0.1:8545"
    )]
    pub chain_ws_rpc_url: SecretString,

    /// Prefix for secret name to store rp secrets in secret-manager.
    /// The implementation will call `format!("{rp_secret_id_prefix}/{rp_id}")`
    #[clap(long, env = "OPRF_NODE_RP_SECRET_ID_PREFIX", default_value = "oprf/rp")]
    pub rp_secret_id_prefix: String,

    /// Secret Id of the wallet private key.
    #[clap(long, env = "OPRF_NODE_WALLET_PRIVATE_KEY_SECRET_ID")]
    pub wallet_private_key_secret_id: String,

    /// The location of the zkey for the key-gen proof in round 2 of KeyGen
    #[clap(long, env = "OPRF_NODE_KEY_GEN_ZKEY")]
    pub key_gen_zkey_path: PathBuf,

    /// The location of the graph binary for the key-gen witness extension
    #[clap(long, env = "OPRF_NODE_KEY_GEN_GRAPH")]
    pub key_gen_witness_graph_path: PathBuf,
}
