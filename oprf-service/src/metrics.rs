pub const METRICS_KEY_OPRF_SUCCESS: &str = "oprf.success";

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    metrics::describe_counter!(
        METRICS_KEY_OPRF_SUCCESS,
        metrics::Unit::Count,
        "Number of successful OPRF evaluations"
    );
}
