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
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`oprf`] – handles OPRF sessions, including initialization and finalization.
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays
pub(crate) mod merkle_watcher;
pub(crate) mod oprf;
pub(crate) mod signature_history;
