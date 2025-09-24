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

    /// The max amount the registry stores merkle roots
    #[clap(long, env = "OPRF_MAX_ROOT_CACHE_SIZE", default_value = "10")]
    pub max_root_cache_size: usize,

    /// The initial size of the public key registry (the merkle tree).
    #[clap(long, env = "OPRF_SC_INIT_PK_REGISTRY_SIZE", default_value = "1")]
    pub init_registry_size: usize,

    /// The interval in which new public keys are added to merkle tree
    #[clap(long, env = "OPRF_SC_ADD_PK_INTERVAL", default_value = "10s", value_parser=humantime::parse_duration)]
    pub add_pk_interval: Duration,

    /// The initial size of the RP registry. The secrets need to be computed.
    #[clap(long, env = "OPRF_SC_INIT_RP_REGISTRY_SIZE", default_value = "1000")]
    pub init_rp_registry: usize,

    /// The interval in which new rps register to the service
    #[clap(long, env = "OPRF_SC_ADD_RP_INTERVAL", default_value = "1h", value_parser=humantime::parse_duration)]
    pub add_rp_interval: Duration,

    /// The seed to compute the merkle tree
    #[clap(long, env = "OPRF_SC_SEED_FOR_REGISTRY", default_value = "42")]
    pub seed: u64,

    /// The amount of OPRF-Services
    #[clap(long, env = "OPRF_SC_OPRF_SERVICES")]
    pub oprf_services: usize,

    /// The degree of the polynomial (the threshold).
    #[clap(long, env = "OPRF_SC_THRESHOLD")]
    pub oprf_degree: u16,

    /// The secret id where the mock finds the public keys in AWS
    #[clap(long, env = "OPRF_SC_PUBLIC_KEYS_AWS", default_value = "oprf/sc/pubs")]
    pub oprf_public_keys_secret_id: String,
}
