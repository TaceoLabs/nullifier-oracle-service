//! Telemetry setup for the OPRF service.
//!
//! This module centralizes configuration and initialization of observability:
//!
//! * Reading service name, tracing endpoint and metrics exporter settings
//!   from environment variables into [`ServiceConfig`], [`MetricsConfig`] and
//!   related structs.
//! * Setting up logging/tracing (Datadog or a default `tracing-subscriber`).
//! * Installing metrics exporters (Datadog, StatsD or Prometheus) based on
//!   the chosen [`MetricsConfig`].
//!
//! Call [`initialize_tracing`] once at startup to configure tracing and metrics.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use std::{backtrace::Backtrace, panic};

use eyre::Context;
use metrics_exporter_dogstatsd::DogStatsDBuilder;
use secrecy::{ExposeSecret, SecretString};
use telemetry_batteries::tracing::{TracingShutdownHandle, datadog::DatadogBattery};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Configuration for telemetry (tracing + metrics) of the service.
///
/// Typically constructed from environment variables via [`ServiceConfig::try_from_env`]
/// and passed to [`initialize_tracing`] during startup.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name - used for logging, Datadog metrics and tracing
    pub service_name: Option<String>,
    /// Traces
    pub traces_endpoint: Option<String>,
    /// Metrics
    pub metrics: Option<MetricsConfig>,
}

impl ServiceConfig {
    /// Build a [`ServiceConfig`] from environment variables.
    ///
    /// Looks for:
    /// * `TRACING_SERVICE_NAME`
    /// * `TRACING_ENDPOINT`
    ///
    /// plus metrics-related variables for [`MetricsConfig`].
    pub fn try_from_env() -> eyre::Result<Self> {
        let service_name = match std::env::var("TRACING_SERVICE_NAME") {
            Ok(name) => Some(name),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!("Failed to read SERVICE_NAME from environment: {}", e);
            }
        };
        let traces_endpoint = match std::env::var("TRACING_ENDPOINT") {
            Ok(endpoint) => Some(endpoint),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!("Failed to read TRACING_ENDPOINT from environment: {}", e);
            }
        };

        let metrics_config = MetricsConfig::try_from_env()?;

        Ok(Self {
            service_name,
            traces_endpoint,
            metrics: metrics_config,
        })
    }
}

/// Metrics exporter configuration.
///
/// Decides which backend (Datadog, StatsD or Prometheus) to use.
#[derive(Debug, Clone)]
pub enum MetricsConfig {
    /// Datadog config
    Datadog(DatadogMetricsConfig),
    /// StatsD config
    StatsD(StatsDMetricsConfig),
    /// Prometheus config
    Prometheus(PrometheusMetricsConfig),
}

impl MetricsConfig {
    /// Build a [`MetricsConfig`] from environment variables.
    ///
    /// Reads `METRICS_EXPORTER` to decide the backend and delegates to the
    /// corresponding `try_from_env` for the chosen type.
    pub fn try_from_env() -> eyre::Result<Option<Self>> {
        match std::env::var("METRICS_EXPORTER") {
            Ok(choice) => match choice.trim().to_lowercase().as_str() {
                "datadog" => Ok(Some(Self::Datadog(
                    DatadogMetricsConfig::try_from_env()
                        .context("during constructing Datadog metrics exporter from environment")?,
                ))),
                "statsd" => Ok(Some(Self::StatsD(
                    StatsDMetricsConfig::try_from_env()
                        .context("during constructing StatsD metrics exporter from environment")?,
                ))),
                "prometheus" => Ok(Some(Self::Prometheus(
                    PrometheusMetricsConfig::try_from_env().context(
                        "during constructing Prometheus metrics exporter from environment",
                    )?,
                ))),
                _ => eyre::bail!(
                    "environment: METRICS_EXPORTER must be \"datadog\", \"statsd\", or \"prometheus\", not \"{}\"",
                    choice
                ),
            },
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => {
                eyre::bail!("Failed to read METRICS_EXPORTER from environment: {}", e);
            }
        }
    }
}

/// Datadog metrics exporter configuration (DogStatsD).
#[derive(Debug, Clone)]
pub struct DatadogMetricsConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) prefix: Option<String>,
}

impl DatadogMetricsConfig {
    /// Build a [`DatadogMetricsConfig`] from environment variables:
    /// * `METRICS_DATADOG_HOST`
    /// * `METRICS_DATADOG_PORT` (optional, defaults to 8125)
    /// * `METRICS_DATADOG_PREFIX` (optional)
    pub fn try_from_env() -> eyre::Result<Self> {
        let host = match std::env::var("METRICS_DATADOG_HOST") {
            Ok(host) => host,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_DATADOG_HOST from environment: {}",
                    e
                );
            }
        };
        let port = match std::env::var("METRICS_DATADOG_PORT") {
            Ok(port) => match port.parse() {
                Ok(port) => port,
                Err(e) => {
                    eyre::bail!("Failed to parse port from METRICS_DATADOG_PORT: {}", e);
                }
            },
            Err(std::env::VarError::NotPresent) => 8125u16,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_DATADOG_PORT from environment: {}",
                    e
                );
            }
        };
        let prefix = match std::env::var("METRICS_DATADOG_PREFIX") {
            Ok(prefix) => Some(prefix),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_DATADOG_PREFIX from environment: {}",
                    e
                );
            }
        };
        Ok(Self { host, port, prefix })
    }
}

/// StatsD metrics exporter configuration.
#[derive(Debug, Clone)]
pub struct StatsDMetricsConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) prefix: Option<String>,
    pub(crate) queue_size: Option<usize>,
    pub(crate) buffer_size: Option<usize>,
}

impl StatsDMetricsConfig {
    /// Build a [`StatsDMetricsConfig`] from environment variables:
    /// * `METRICS_STATSD_HOST` / `PORT` (port defaults to 8125)
    /// * Optional `PREFIX`, `QUEUE_SIZE`, `BUFFER_SIZE`
    pub fn try_from_env() -> eyre::Result<Self> {
        let host = match std::env::var("METRICS_STATSD_HOST") {
            Ok(host) => host,
            Err(e) => {
                eyre::bail!("Failed to read METRICS_STATSD_HOST from environment: {}", e);
            }
        };
        let port = match std::env::var("METRICS_STATSD_PORT") {
            Ok(port) => match port.parse() {
                Ok(port) => port,
                Err(e) => {
                    eyre::bail!("Failed to parse port from METRICS_STATSD_PORT: {}", e);
                }
            },
            Err(std::env::VarError::NotPresent) => 8125u16,
            Err(e) => {
                eyre::bail!("Failed to read METRICS_STATSD_PORT from environment: {}", e);
            }
        };
        let prefix = match std::env::var("METRICS_STATSD_PREFIX") {
            Ok(prefix) => Some(prefix),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_STATSD_PREFIX from environment: {}",
                    e
                );
            }
        };
        let queue_size = match std::env::var("METRICS_STATSD_QUEUE_SIZE") {
            Ok(queue_size) => Some(
                queue_size
                    .parse()
                    .context("during reading METRICS_STATSD_QUEUE_SIZE from environment")?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_STATSD_QUEUE_SIZE from environment: {}",
                    e
                );
            }
        };
        let buffer_size = match std::env::var("METRICS_STATSD_BUFFER_SIZE") {
            Ok(buffer_size) => Some(
                buffer_size
                    .parse()
                    .context("during reading METRICS_STATSD_BUFFER_SIZE from environment")?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_STATSD_BUFFER_SIZE from environment: {}",
                    e
                );
            }
        };
        Ok(Self {
            host,
            port,
            prefix,
            queue_size,
            buffer_size,
        })
    }
}

/// Prometheus metrics exporter configuration.
#[derive(Debug, Clone)]
pub enum PrometheusMetricsConfig {
    /// Prometheus scrape endpoint (the service exposes metrics over HTTP).
    Scrape(ScrapePrometheusMetricsConfig),
    /// Push mode (service pushes metrics to a gateway).
    Push(PushPrometheusMetricsConfig),
}

impl PrometheusMetricsConfig {
    /// Build a [`PrometheusMetricsConfig`] from environment variables:
    /// * `METRICS_PROMETHEUS_MODE` (must be `scrape` or `push`)
    ///
    /// plus mode-specific variables.
    pub fn try_from_env() -> eyre::Result<Self> {
        match std::env::var("METRICS_PROMETHEUS_MODE") {
            Ok(choice) => match choice.trim().to_lowercase().as_str() {
                "scrape" => Ok(Self::Scrape(ScrapePrometheusMetricsConfig::try_from_env()?)),
                "push" => Ok(Self::Push(PushPrometheusMetricsConfig::try_from_env()?)),
                _ => eyre::bail!(
                    "environment: METRICS_PROMETHEUS_MODE must be \"scrape\" or \"push\", not \"{}\"",
                    choice
                ),
            },
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_MODE from environment: {}",
                    e
                );
            }
        }
    }
}

/// Scrape mode Prometheus metrics configuration.
#[derive(Debug, Clone)]
pub struct ScrapePrometheusMetricsConfig {
    pub(crate) bind_addr: Option<SocketAddr>,
}

impl ScrapePrometheusMetricsConfig {
    /// Build a [`ScrapePrometheusMetricsConfig`] from environment variable
    /// `METRICS_PROMETHEUS_BIND_ADDR` (optional).
    pub fn try_from_env() -> eyre::Result<Self> {
        match std::env::var("METRICS_PROMETHEUS_BIND_ADDR") {
            Ok(bind_addr) => Ok(ScrapePrometheusMetricsConfig {
                bind_addr: Some(
                    bind_addr
                        .parse()
                        .context("during reading METRICS_PROMETHEUS_BIND_ADDR from environment")?,
                ),
            }),
            Err(std::env::VarError::NotPresent) => {
                Ok(ScrapePrometheusMetricsConfig { bind_addr: None })
            }
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_BIND_ADDR from environment: {}",
                    e
                );
            }
        }
    }
}

/// Push mode Prometheus metrics configuration.
#[derive(Debug, Clone)]
pub struct PushPrometheusMetricsConfig {
    pub(crate) endpoint: String,
    pub(crate) interval: Duration,
    pub(crate) username: Option<SecretString>,
    pub(crate) password: Option<SecretString>,
    pub(crate) use_http_post_method: bool,
}
impl PushPrometheusMetricsConfig {
    /// Build a [`PushPrometheusMetricsConfig`] from environment variables:
    /// `METRICS_PROMETHEUS_ENDPOINT`, `INTERVAL`, `USERNAME`, `PASSWORD`,
    /// `USE_HTTP_POST_METHOD`.
    pub fn try_from_env() -> eyre::Result<Self> {
        let endpoint = match std::env::var("METRICS_PROMETHEUS_ENDPOINT") {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_ENDPOINT from environment: {}",
                    e
                );
            }
        };
        let interval = match std::env::var("METRICS_PROMETHEUS_INTERVAL") {
            Ok(interval) => {
                std::time::Duration::from(humantime::Duration::from_str(&interval).context(
                    "During parsing METRICS_PROMETHEUS_INTERVAL from env: \
                              Expecting a duration string such as \"1h 24min\", \"29s\", ..",
                )?)
            }
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_INTERVAL from environment: {}",
                    e
                );
            }
        };
        let username = match std::env::var("METRICS_PROMETHEUS_USERNAME") {
            Ok(username) => Some(SecretString::from(username)),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_USERNAME from environment: {}",
                    e
                );
            }
        };
        let password = match std::env::var("METRICS_PROMETHEUS_PASSWORD") {
            Ok(password) => Some(SecretString::from(password)),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_PASSWORD from environment: {}",
                    e
                );
            }
        };
        let use_http_post_method = match std::env::var("METRICS_PROMETHEUS_USE_HTTP_POST_METHOD") {
            Ok(use_http_post_method) => use_http_post_method.parse().context(
                "during reading METRICS_PROMETHEUS_USE_HTTP_POST_METHOD from environment (expecting bool)",
            )?,
            Err(std::env::VarError::NotPresent) => false,
            Err(e) => {
                eyre::bail!(
                    "Failed to read METRICS_PROMETHEUS_USE_HTTP_POST_METHOD from environment: {}",
                    e
                );
            }
        };
        Ok(PushPrometheusMetricsConfig {
            endpoint,
            interval,
            username,
            password,
            use_http_post_method,
        })
    }
}

/// Initialize metrics exporter according to [`MetricsConfig`].
///
/// Called internally by [`initialize_tracing`] once configuration is loaded.
pub fn initialize_metrics(config: &MetricsConfig) -> eyre::Result<()> {
    match config {
        MetricsConfig::Datadog(datadog_conf) => {
            tracing::debug!("Setting up Datadog metrics exporter ..");
            let mut builder = DogStatsDBuilder::default()
                .with_remote_address(format!("{}:{}", &datadog_conf.host, datadog_conf.port))?
                .send_histograms_as_distributions(true);
            if let Some(prefix) = &datadog_conf.prefix {
                builder = builder.set_global_prefix(prefix);
            };
            builder.install()?;
        }
        MetricsConfig::StatsD(statsd_conf) => {
            tracing::debug!("Setting up StatsD metrics exporter ..");
            let builder = metrics_exporter_statsd::StatsdBuilder::from(
                statsd_conf.host.to_owned(),
                statsd_conf.port,
            );
            let builder = {
                if let Some(buffer_size) = statsd_conf.buffer_size {
                    builder.with_buffer_size(buffer_size)
                } else {
                    builder
                }
            };
            let builder = {
                if let Some(queue_size) = statsd_conf.queue_size {
                    builder.with_queue_size(queue_size)
                } else {
                    builder
                }
            };
            let recorder = builder
                .build(statsd_conf.prefix.as_deref())
                .context("during building StatsD metrics exporter")?;
            metrics::set_global_recorder(recorder)
                .context("during setting StatsD metrics exporter as global recorder")?;
        }
        MetricsConfig::Prometheus(prometheus_conf) => match prometheus_conf {
            PrometheusMetricsConfig::Scrape(scrape_conf) => {
                tracing::debug!("Setting up Prometheus scrape metrics exporter ..");
                let builder = if let Some(bind_addr) = scrape_conf.bind_addr {
                    metrics_exporter_prometheus::PrometheusBuilder::new()
                        .with_http_listener(bind_addr)
                } else {
                    metrics_exporter_prometheus::PrometheusBuilder::new()
                };
                builder.install().context(
                    "during installing Prometheus scrape metrics exporter as global recorder",
                )?;
            }
            PrometheusMetricsConfig::Push(push_conf) => {
                tracing::debug!("Setting up Prometheus push metrics exporter ..");
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .with_push_gateway(
                        &push_conf.endpoint,
                        push_conf.interval,
                        push_conf
                            .username
                            .to_owned()
                            .map(|x| x.expose_secret().to_owned()),
                        push_conf
                            .password
                            .to_owned()
                            .map(|x| x.expose_secret().to_owned()),
                        push_conf.use_http_post_method,
                    )
                    .context("during building Prometheus push metrics exporter")?
                    .install()
                    .context(
                        "during installing Prometheus push metrics exporter as global recorder",
                    )?;
            }
        },
    };
    Ok(())
}

/// Initializes structured logging/tracing for the service.
///
/// Depending on the [`ServiceConfig`]:
///
/// * If a `service_name` is set, Datadog tracing is initialized and a custom
///   panic hook is installed. The hook logs panic messages and their backtraces
///   as a single line to make them easier to ingest by log aggregators.
/// * Otherwise, a default `tracing-subscriber` registry with human-readable
///   formatting and an environment-based filter is installed.
///
/// If the configuration also contains metrics settings, [`initialize_metrics`]
/// is called automatically.
///
/// # Returns
/// - `Ok(Some(handle))` if Datadog tracing was started. The [`TracingShutdownHandle`]
///   can be used to flush/stop traces on shutdown.
/// - `Ok(None)` if only the default `tracing` subscriber was set up.
/// - An error if tracing or metrics initialization failed.
///
/// This is intended as a one-time setup call during service startup.
pub fn initialize_tracing(config: &ServiceConfig) -> eyre::Result<Option<TracingShutdownHandle>> {
    let handle = {
        if let Some(service_name) = config.service_name.as_deref() {
            let tracing_shutdown_handle =
                DatadogBattery::init(config.traces_endpoint.as_deref(), service_name, None, true);
            // Set a custom panic hook to print backtraces on one line
            panic::set_hook(Box::new(|panic_info| {
                let message = match panic_info.payload().downcast_ref::<&str>() {
                    Some(s) => *s,
                    None => match panic_info.payload().downcast_ref::<String>() {
                        Some(s) => s.as_str(),
                        None => "Unknown panic message",
                    },
                };
                let location = if let Some(location) = panic_info.location() {
                    format!(
                        "{}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    )
                } else {
                    "Unknown location".to_string()
                };

                let backtrace = Backtrace::capture();
                let backtrace_string = format!("{backtrace:?}");

                let backtrace_single_line = backtrace_string.replace('\n', " | ");

                tracing::error!(
                    { backtrace = %backtrace_single_line, location = %location},
                    "Panic occurred with message: {}",
                    message
                );
            }));
            Ok(Some(tracing_shutdown_handle))
        } else {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(false)
                        .with_line_number(false),
                )
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "oprf_service=trace,warn".into()),
                )
                .init();

            Ok(None)
        }
    };

    if let Some(metrics_conf) = &config.metrics {
        initialize_metrics(metrics_conf)?;
    }

    handle
}
