use std::sync::Arc;

use eyre::Context as _;
use oprf_types::crypto::{PartyId, PeerPublicKey, PeerPublicKeyList};

use crate::config::SmartContractMockConfig;

#[derive(Clone)]
pub(crate) struct OprfPeerKeyRegistry(Arc<Vec<PeerPublicKey>>);

impl From<PeerPublicKeyList> for OprfPeerKeyRegistry {
    fn from(value: PeerPublicKeyList) -> Self {
        Self(Arc::new(value.into_inner()))
    }
}

impl OprfPeerKeyRegistry {
    pub(crate) async fn load_from_aws(config: &SmartContractMockConfig) -> eyre::Result<Self> {
        tracing::info!(
            "loading OPRF peer public keys from {}",
            config.oprf_public_keys_secret_id
        );
        let aws_config = aws_config::load_from_env().await;
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);
        let public_keys = client
            .get_secret_value()
            .secret_id(config.oprf_public_keys_secret_id.clone())
            .send()
            .await
            .context("while retrieving public keys from peers")?
            .secret_string()
            .ok_or_else(|| eyre::eyre!("cannot find secret with provided name"))?
            .to_owned();
        let keys = serde_json::from_str::<PeerPublicKeyList>(&public_keys)
            .context("while deserializing peer keys")?;
        if config.oprf_services != keys.len() {
            eyre::bail!(
                "expected {} keys in AWS but only found {}",
                config.oprf_services,
                keys.len()
            );
        }
        Ok(Self::from(keys))
    }

    pub(crate) fn get_party_id(&self, needle: PeerPublicKey) -> Option<PartyId> {
        self.0
            .iter()
            .position(|hay| needle == *hay)
            .map(|x| PartyId::from(u16::try_from(x).expect("fits into u16")))
    }
}
