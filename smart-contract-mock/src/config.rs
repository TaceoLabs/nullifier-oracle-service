use std::{net::SocketAddr, time::Duration};

use clap::Parser;

/// The configuration for the Smart Contract Mock Server.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct SmartContractMockConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_SC_BIND_ADDR", default_value = "0.0.0.0:6789")]
    pub bind_addr: SocketAddr,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_MAX_ROOT_CACHE_SIZE", default_value = "10000")]
    pub max_root_cache_size: usize,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_SC_INIT_REGISTRY_SIZE", default_value = "10000")]
    pub init_registry_size: usize,

    /// The interval in which new public keys are added
    #[clap(long, env = "OPRF_SC_ADD_PK_INTERVAL", default_value = "5s", value_parser=humantime::parse_duration)]
    pub add_pk_interval: Duration,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_SC_SEED_FOR_REGISTRY", default_value = "42")]
    pub seed: u64,

    /// The amount of OPRF-Services
    #[clap(long, env = "OPRF_SC_OPRF_SERVICES")]
    pub oprf_services: usize,
}
