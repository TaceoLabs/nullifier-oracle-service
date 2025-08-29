use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use oprf_core::ddlog_equality::DLogEqualitySession;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    config::OprfConfig,
    metrics::{METRICS_KEY_DELETED_SESSION, METRICS_KEY_OPEN_SESSIONS},
};

type SessionsMap = Arc<Mutex<HashMap<Uuid, Session>>>;

struct Session {
    randomness: DLogEqualitySession,
    creation: Instant,
}

impl From<DLogEqualitySession> for Session {
    fn from(randomness: DLogEqualitySession) -> Self {
        Self {
            randomness,
            creation: Instant::now(),
        }
    }
}

/// The Session Store of the OPRF service. Provides an interface to the
/// currently open sessions.
/// In the background, the session store is a thin wrapper about a Mutex
/// protecting a HashMap.
///
/// When spawning a session store, the implementation will spawn an
/// additional cleanup task.
///
/// The cleanup task will periodically cleanup old sessions, as defined
/// by the config.
#[derive(Clone)]
pub(crate) struct SessionStore {
    sessions: SessionsMap,
}

fn start_cleanup_task(sessions: SessionsMap, interval: Duration, request_lifetime: Duration) {
    // Start the cleanup interval task
    let mut cleanup_interval = tokio::time::interval(interval);
    tokio::task::spawn(async move {
        // ignore the first tick
        cleanup_interval.tick().await;
        loop {
            cleanup_interval.tick().await;

            let deleted = {
                let mut sessions = sessions.lock().expect("not poisoned");
                let _guard = tracing::debug_span!("cleanup task").entered();
                let cutoff_time = Instant::now();
                tracing::debug!("starting cleanup");
                let old_size = sessions.len();
                // Retain on HashMap is not very friendly as it has runtime O(capacity) and not O(n). We may need to rewrite this if we see that it takes a significant amount of time.
                sessions.retain(|_, v| cutoff_time.duration_since(v.creation) < request_lifetime);
                let new_size = sessions.len();
                let deleted = old_size - new_size;
                tracing::debug!(
                    "removed {} elements, new len: {}",
                    old_size - new_size,
                    new_size
                );
                deleted
            };
            metrics::gauge!(METRICS_KEY_OPEN_SESSIONS).decrement(deleted as f64);
            metrics::counter!(METRICS_KEY_DELETED_SESSION).increment(deleted as u64);
        }
    });
}

impl SessionStore {
    pub(crate) fn init(config: Arc<OprfConfig>) -> Self {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        // start the periodic tasks for cleanup
        start_cleanup_task(
            sessions.clone(),
            config.session_cleanup_interval,
            config.request_lifetime,
        );

        Self { sessions }
    }

    #[instrument(level = "debug", skip(self, session))]
    pub(crate) fn store(&self, request_id: Uuid, session: DLogEqualitySession) {
        tracing::debug!("storing session for {request_id}");
        tracing::trace!("trying to get lock...");
        let inc = {
            let mut sessions = self.sessions.lock().expect("not poisoned");
            tracing::trace!("got lock");
            let old_session = sessions.insert(request_id, Session::from(session));
            old_session.is_some()
        };
        if inc {
            metrics::gauge!(METRICS_KEY_OPEN_SESSIONS).increment(1);
        } else {
            tracing::warn!("already had a session with this id - removing old session");
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) fn retrieve(&self, request_id: Uuid) -> Option<DLogEqualitySession> {
        tracing::debug!("retrieving session {request_id}");
        tracing::trace!("trying to get lock...");
        let session = {
            let mut sessions = self.sessions.lock().expect("not poisoned");
            tracing::trace!("got lock");
            sessions.remove(&request_id)
        };
        if session.is_some() {
            metrics::gauge!(METRICS_KEY_OPEN_SESSIONS).decrement(1);
        }
        // We return the randomness even if we exceeded the deadline. There is no problem with old sessions, we have the deadline only to not pollute the RAM with old sessions
        session.map(|s| s.randomness)
    }
}
