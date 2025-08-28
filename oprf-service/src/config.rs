use std::{net::SocketAddr, time::Duration};

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

/// The configuration for the CCL OPRF service.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct ServiceConfig {
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

    /// Interval for the Session cleanup task to do its thing.
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
}
