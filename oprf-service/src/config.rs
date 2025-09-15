use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};

/// The environment the service is running in.
///
/// TODO: explain differences between environments.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Enviroment {
    /// Production environment.
    Prod,
    /// Development environment.
    Dev,
}

impl Enviroment {
    pub fn assert_is_dev(&self) {
        assert!(matches!(self, Enviroment::Dev), "Is not dev environment")
    }
}

/// The configuration for the OPRF service.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfConfig {
    /// S3 bucket for file storage/sharing
    #[clap(long, env = "OPRF_SERVICE_ENVIRONMENT", default_value = "dev")]
    pub environment: Enviroment,

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

    /// Chain URL.
    /// TODO this is heavy wip, and will change. This notice
    /// is here to be removed as soon as the design gets more clear
    #[clap(long, env = "OPRF_SERVICE_CHAIN_URL")]
    pub chain_url: String,

    /// Interval to check the key rotation commands on the smart contract.
    #[clap(
        long,
        env = "OPRF_SERVICE_CHAIN_CHECK_INTERVAL",
        default_value = "1min",
        value_parser = humantime::parse_duration

    )]
    pub chain_check_interval: Duration,

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
}
