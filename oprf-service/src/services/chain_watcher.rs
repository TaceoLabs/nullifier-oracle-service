#[cfg(feature = "mock-chain-watcher")]
mod http_mock;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "mock-chain-watcher")]
pub(crate) use http_mock::spawn_mock_watcher;
use serde::Deserialize;
use serde::Serialize;

/// Represents an epoch of a merkle-root. Users will provide a `MrEpoch` and retrieve the associated [`MerkleRoot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct MerkleEpoch(u128);

/// Represents an epoch for the key share.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub(crate) struct KeyEpoch(u128);

/// The type of a MerkleRoot.
/// Is a Field element in Bn254.
pub(crate) type MerkleRoot = ark_bn254::Fr;

/// Dyn trait for the watcher service. Must be `Send` + `Sync` to work with Axum.
pub(crate) type ChainWatcherService = Arc<dyn ChainWatcher + Send + Sync>;

/// TODO
#[derive(Debug, thiserror::Error)]
pub(crate) enum ChainWatcherError {
    #[error("Requested epoch too far in the future")]
    EpochTooFar,
    #[error("Epoch is too old")]
    EpochTooOld,
    #[error("Cannot find epoch: {0:?}")]
    UnknownEpoch(MerkleEpoch),
    #[error("Could not check chain events: {0:?}")]
    #[expect(dead_code)]
    CouldNotCheckChainEvents(#[source] eyre::Report),
}

#[async_trait]
pub(crate) trait ChainWatcher {
    /// Retrieves a merkle root by epoch.
    ///
    /// If the epoch is in the cache immediately returns the merkle root.
    /// If the epoch is not in the cache potentially refreshes if epoch not too far in the future.
    async fn get_merkle_root_by_epoch(
        &self,
        epoch: MerkleEpoch,
    ) -> Result<MerkleRoot, ChainWatcherError>;

    /// TODO
    async fn check_chain_events(&self) -> Result<(), ChainWatcherError>;
}

impl MerkleEpoch {
    fn should_refresh(
        &self,
        other: MerkleEpoch,
        max_difference: u128,
    ) -> Result<(), ChainWatcherError> {
        match u128::cmp(&self.0, &other.0) {
            std::cmp::Ordering::Less => {
                // works because we checked that self.0 is less than other.0
                if other.0 - self.0 > max_difference {
                    Err(ChainWatcherError::EpochTooFar)
                } else {
                    Ok(())
                }
            }
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => Err(ChainWatcherError::EpochTooOld),
        }
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}
