pub const METRICS_KEY_OPRF_SUCCESS: &str = "oprf.success";
pub const METRICS_KEY_OPEN_SESSIONS: &str = "oprf.sessions.open";
pub const METRICS_KEY_DELETED_SESSION: &str = "oprf.sessions.deleted";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_KEY_OPRF_SUCCESS,
        metrics::Unit::Count,
        "Number of successful OPRF evaluations"
    );

    metrics::describe_gauge!(
        METRICS_KEY_OPEN_SESSIONS,
        metrics::Unit::Count,
        "Number of open sessions the service has stored"
    );

    metrics::describe_counter!(
        METRICS_KEY_DELETED_SESSION,
        metrics::Unit::Count,
        "Number of sessions that were removed because they exceeded the deadline"
    );
}
