//! Core services of the OPRF peer.
//!
//! This module exposes all internal services used by the peer to handle
//! cryptography, chain interactions, secret generation, OPRF sessions, and
//! session storage. Each service is designed to encapsulate a specific
//! responsibility and can be used by higher-level components such as the API
//! or the main application state.
//!
//! # Services overview
//!
//! - [`chain_watcher`] – watches the blockchain for events relevant to the peer.
//! - [`crypto_device`] – manages cryptographic operations and key material.
//! - [`event_handler`] – handles chain events sequentially to avoid locks.
//! - [`oprf`] – handles OPRF sessions, including initialization and finalization.
//! - [`secret_gen`] – handles multi-round secret generation protocols.
//! - [`secret_manager`] – stores and retrieves secrets (AWS or local file based).
//! - [`session_store`] – stores ephemeral session randomness for OPRF requests.
pub(crate) mod chain_watcher;
pub(crate) mod crypto_device;
pub(crate) mod event_handler;
pub(crate) mod oprf;
pub(crate) mod secret_gen;
pub(crate) mod secret_manager;
pub(crate) mod session_store;
