//! Metrics definitions for the OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Metrics key for registered DLogSecrets.
pub const METRICS_RP_SECRETS: &str = "oprf.rp.secrets";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_RP_SECRETS,
        metrics::Unit::Count,
        "Number of RPs for which the node holds secrets"
    );
}
