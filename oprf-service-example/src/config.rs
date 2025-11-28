//! Configuration types and CLI/environment parsing for the OPRF service.

use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use oprf_service::config::OprfNodeConfig;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct ExampleOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF service config
    #[clap(flatten)]
    pub service_config: OprfNodeConfig,
}
