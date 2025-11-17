//! Session Store
//!
//! This module provides an in-memory session store for the OPRF service.
//! Each session holds a [`DLogSessionShamir`] and is identified by a UUID.
//!
//! Sessions are automatically cleaned up after a configured lifetime. The store
//! exposes methods to store and retrieve sessions while updating metrics for
//! open and deleted sessions.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use oprf_core::ddlog_equality::shamir::DLogSessionShamir;
use parking_lot::Mutex;
use tracing::instrument;
use uuid::Uuid;

use crate::metrics::{METRICS_KEY_DELETED_SESSION, METRICS_KEY_OPEN_SESSIONS};

type SessionsMap = Arc<Mutex<HashMap<Uuid, Session>>>;

/// Defines a dedicated Session.
///
/// It holds the randomness created during initial creation and a timestamp.
/// If the timestamp exceeds a defined amount, the session will be removed
/// from the store.
struct Session {
    randomness: DLogSessionShamir,
    creation: Instant,
}

impl From<DLogSessionShamir> for Session {
    fn from(randomness: DLogSessionShamir) -> Self {
        Self {
            randomness,
            creation: Instant::now(),
        }
    }
}

/// The Session Store of the OPRF service.
///
/// Provides an interface to manage currently open sessions. Each session
/// holds a [`DLogSessionShamir`] and a creation timestamp.  
/// Old sessions are periodically removed by a background cleanup task.
#[derive(Clone)]
pub(crate) struct SessionStore {
    sessions: SessionsMap,
}

impl SessionStore {
    /// Initializes a new `SessionStore` and starts the background cleanup task.
    ///
    /// # Arguments
    /// * `config` - The service configuration providing cleanup interval and request lifetime.
    pub(crate) fn init(session_cleanup_interval: Duration, request_lifetime: Duration) -> Self {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        // start the periodic tasks for cleanup
        start_cleanup_task(sessions.clone(), session_cleanup_interval, request_lifetime);

        Self { sessions }
    }

    /// Stores a session with the given request ID.
    ///
    /// If a session with the same ID already exists, it will be replaced
    ///
    /// # Arguments
    /// * `request_id` - Unique ID of the session.
    /// * `session` - The [`DLogSessionShamir`] to store.
    #[instrument(level = "debug", skip(self, session))]
    pub(crate) fn insert(&self, request_id: Uuid, session: DLogSessionShamir) {
        tracing::debug!("storing session for {request_id}");
        tracing::trace!("trying to get lock...");
        let inc = {
            let mut sessions = self.sessions.lock();
            tracing::trace!("got lock");
            let old_session = sessions.insert(request_id, Session::from(session));
            old_session.is_none()
        };
        if inc {
            metrics::gauge!(METRICS_KEY_OPEN_SESSIONS).increment(1);
        } else {
            tracing::warn!("already had a session with this id - removing old session");
        }
    }

    /// Retrieves and removes a session with the given request ID.
    ///
    /// If the session exists, it is removed from the store and returned.
    /// If a session is past its lifetime, but was not cleaned up by the
    /// cleanup task, this method will still return the session,
    /// regardless of the lifetime.
    ///
    /// # Arguments
    /// * `request_id` - Unique ID of the session.
    ///
    /// # Returns
    /// Optionally returns the [`DLogSessionShamir`] if it exists.
    #[instrument(level = "debug", skip(self))]
    pub(crate) fn remove(&self, request_id: Uuid) -> Option<DLogSessionShamir> {
        tracing::debug!("retrieving session {request_id}");
        tracing::trace!("trying to get lock...");
        let session = {
            let mut sessions = self.sessions.lock();
            tracing::trace!("got lock");
            sessions.remove(&request_id)
        };
        if session.is_some() {
            metrics::gauge!(METRICS_KEY_OPEN_SESSIONS).decrement(1);
        }
        // We return the randomness even if we exceeded the deadline. There is no problem with old sessions, we have the deadline only to not pollute the RAM with old sessions
        session.map(|s| s.randomness)
    }

    /// Checks if a session with the given request ID exists in the store without removing it.
    ///
    /// This method verifies the existence of a session with the specified request ID in the store.
    /// It does not remove the session, regardless of whether it is past its lifetime.
    ///
    /// # Arguments
    /// * `request_id` - Unique ID of the session.
    ///
    /// # Returns
    /// `true` if the session exists, `false` otherwise.
    #[instrument(level = "debug", skip(self))]
    #[allow(dead_code)]
    pub(crate) fn contains_key(&self, request_id: Uuid) -> bool {
        let sessions = self.sessions.lock();
        tracing::trace!("got lock");
        sessions.contains_key(&request_id)
    }
}

/// Starts the periodic cleanup task for removing old sessions.
///
/// The task ticks in the the provided interval. In this interval,
/// while check for Sessions exceeding `request_lifetime` and removes
/// them from the store.
///
/// # Arguments
/// * `sessions` - Shared session map.
/// * `interval` - How often to check for expired sessions.
/// * `request_lifetime` - Maximum lifetime of a session.
fn start_cleanup_task(sessions: SessionsMap, interval: Duration, request_lifetime: Duration) {
    // Start the cleanup interval task
    let mut cleanup_interval = tokio::time::interval(interval);
    tokio::task::spawn(async move {
        // ignore the first tick
        cleanup_interval.tick().await;
        loop {
            cleanup_interval.tick().await;

            let deleted = {
                let mut sessions = sessions.lock();
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
