//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Metrics key for counting successful OPRF evaluations
pub const METRICS_KEY_OPRF_SUCCESS: &str = "oprf.success";
/// Metrics key for counting currently running sessions.
pub const METRICS_KEY_OPEN_SESSIONS: &str = "oprf.sessions.open";
/// Metrics key for deleted sessions.
pub const METRICS_KEY_DELETED_SESSION: &str = "oprf.sessions.deleted";
/// Metrics key for registered DLogSecrets.
pub const METRICS_RP_SECRETS: &str = "oprf.rp.secrets";
/// Metrics key for currently stored merkle roots
pub const METRICS_MERKLE_COUNT: &str = "oprf.merkle.count";

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
        "Number of open sessions the peer has stored"
    );

    metrics::describe_counter!(
        METRICS_KEY_DELETED_SESSION,
        metrics::Unit::Count,
        "Number of sessions that were removed because they exceeded the deadline"
    );

    metrics::describe_counter!(
        METRICS_RP_SECRETS,
        metrics::Unit::Count,
        "Number of RPs for which the peer holds secrets"
    );

    metrics::describe_counter!(
        METRICS_MERKLE_COUNT,
        metrics::Unit::Count,
        "Number of RPs for which the peer holds secrets"
    );
}
