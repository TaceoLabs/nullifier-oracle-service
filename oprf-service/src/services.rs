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
//! - [`crypto_device`] – manages cryptographic operations and key material.
//! - [`event_handler`] – handles chain events sequentially to avoid locks.
//! - [`key_event_watcher`] – watches the blockchain for key-generation events relevant to the peer.
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`oprf`] – handles OPRF sessions, including initialization and finalization.
//! - [`secret_gen`] – handles multi-round secret generation protocols.
//! - [`session_store`] – stores ephemeral session randomness for OPRF requests.
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays
pub(crate) mod crypto_device;
pub(crate) mod event_handler;
pub(crate) mod key_event_watcher;
pub(crate) mod merkle_watcher;
pub(crate) mod oprf;
pub(crate) mod secret_gen;
pub(crate) mod session_store;
pub(crate) mod signature_history;
