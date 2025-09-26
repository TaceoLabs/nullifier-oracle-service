use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tracing::instrument;

#[derive(Debug, thiserror::Error)]
#[error("duplicate signature")]
pub(crate) struct DuplicateSignatureError;

#[derive(Clone)]
pub(crate) struct SignatureHistory {
    signatures: Arc<Mutex<HashMap<Vec<u8>, Duration>>>,
}

impl SignatureHistory {
    pub(crate) fn init(max_signature_age: Duration, cleanup_interval: Duration) -> Self {
        let signatures = Arc::new(Mutex::new(HashMap::new()));
        let signature_history = SignatureHistory { signatures };
        let signature_history_clone = signature_history.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                tracing::trace!("cleanup signature history");
                signature_history_clone.cleanup(max_signature_age);
            }
        });
        signature_history
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn add_signature(
        &self,
        signature: Vec<u8>,
        time_stamp: Duration,
    ) -> Result<(), DuplicateSignatureError> {
        tracing::debug!("add signature to history");
        let mut signatures = self.signatures.lock();
        if signatures.contains_key(&signature) {
            tracing::debug!("duplicate signature");
            return Err(DuplicateSignatureError);
        }
        signatures.insert(signature, time_stamp);
        Ok(())
    }

    fn cleanup(&self, max_signature_age: Duration) {
        let mut signatures = self.signatures.lock();
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        signatures
            .retain(|_, time_stamp| current_time.saturating_sub(*time_stamp) < max_signature_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signature_history() {
        // cleanup interval doesn't matter, we call cleanup manually
        let max_signature_age = Duration::from_secs(10);
        let signature_history = SignatureHistory::init(max_signature_age, Duration::from_secs(60));
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        signature_history
            .add_signature(b"foo".to_vec(), current_time - max_signature_age * 2) // this will be removed in cleanup
            .expect("can add signature");
        signature_history
            .add_signature(b"bar".to_vec(), current_time)
            .expect("can add signature");
        // will fail because signature is in history
        assert!(
            signature_history
                .add_signature(b"foo".to_vec(), current_time)
                .is_err()
        );
        // run cleanup once
        signature_history.cleanup(max_signature_age);
        // will succeed because signature was removed in cleanup
        signature_history
            .add_signature(b"foo".to_vec(), current_time)
            .expect("can add signature");
    }
}
