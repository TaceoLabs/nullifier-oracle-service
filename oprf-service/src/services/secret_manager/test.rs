use async_trait::async_trait;
use tracing::instrument;

use crate::services::crypto_device::PeerPrivateKey;
use crate::services::secret_manager::SecretManager;

/// Test secret manager
pub(crate) struct TestSecretManager {
    private_key: PeerPrivateKey,
}

impl TestSecretManager {
    pub(crate) fn new(private_key: PeerPrivateKey) -> Self {
        Self { private_key }
    }
}

#[async_trait]
impl SecretManager for TestSecretManager {
    #[instrument(level = "info", skip_all)]
    async fn load_secrets(&self) -> eyre::Result<PeerPrivateKey> {
        Ok(self.private_key.clone())
    }
}
