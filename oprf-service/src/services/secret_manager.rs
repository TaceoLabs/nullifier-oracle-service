//! Secret manager interface for OPRF peers.
//!
//! This module defines the [`SecretManager`] trait, which is used to
//! retrieve [`PeerPrivateKey`]s
//!
//! Current `SecretManager` implementations:
//! - AWS (cloud storage)
//! - test secret manager (contains initially provided secrets)

use std::sync::Arc;

use async_trait::async_trait;

use crate::services::crypto_device::PeerPrivateKey;

pub mod aws;
#[cfg(test)]
pub(crate) mod test;

/// Dynamic trait object for secret manager service.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type SecretManagerService = Arc<dyn SecretManager + Send + Sync>;

/// Trait that implementations of secret managers must provide.
///
/// Handles fetching of [`PeerPrivateKey`]s
#[async_trait]
pub(crate) trait SecretManager {
    /// Loads the [`PeerPrivateKey`]
    ///
    /// The private key is used for Diffie-Hellman with the smart contract.
    async fn load_secrets(&self) -> eyre::Result<PeerPrivateKey>;
}
