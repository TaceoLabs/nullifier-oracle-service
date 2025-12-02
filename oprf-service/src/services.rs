//! Core services that make up TACEO:Oprf.
//!
//! This module exposes all internal services used by the node to handle
//! cryptography, chain interactions, secret generation, OPRF sessions, and
//! session storage. Each service is designed to encapsulate a specific
//! responsibility and can be used by higher-level components such as the API
//! or the main application state.
//!
//! # Services overview
//!
//! - [`key_event_watcher`] – watches the blockchain for key-generation events relevant to the node.
//! - [`oprf`] – handles OPRF sessions, including initialization and finalization.
//! - [`oprf_key_material_store`] – provides a store that securely holds all OPRF key-material.
//! - [`secret_gen`] – handles multi-round secret generation protocols.
//! - [`secret_manager`] – stores and retrieves secrets.
//! - [`session_store`] – stores ephemeral session randomness for OPRF requests.
pub(crate) mod key_event_watcher;
pub(crate) mod oprf;
pub mod oprf_key_material_store;
pub(crate) mod secret_gen;
pub mod secret_manager;
pub(crate) mod session_store;
