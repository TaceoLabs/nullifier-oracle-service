use std::path::PathBuf;

use clap::Parser;

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfClientConfig {
    /// The URLs to all OPRF Serviceu
    #[clap(
        long,
        env = "OPRF_CLIENT_SERVICES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000, http://127.0.0.1:10001, http://127.0.0.1:10002"
    )]
    pub services: Vec<String>,

    /// Path to the OPRFQuery zkey.
    #[clap(long, env = "OPRF_CLIENT_QUERY_ZKEY_PATH")]
    pub query_zkey_path: PathBuf,

    /// Path to the OPRFNullifier zkey.
    #[clap(long, env = "OPRF_CLIENT_NULLIFIER_ZKEY_PATH")]
    pub nullifier_zkey_path: PathBuf,
}
