//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Metrics key for currently stored merkle roots
pub const METRICS_MERKLE_COUNT: &str = "oprf.merkle.count";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_MERKLE_COUNT,
        metrics::Unit::Count,
        "Number of RPs for which the peer holds secrets"
    );
}
