#![deny(missing_docs)]
//! This crate implements privacy-preserving protocols for verifiable, threshold, and distributed Oblivious Pseudorandom Functions (OPRF) using elliptic curves.
//!
//! Modules include:
//! - **keygen**: Distributed key generation and secret-sharing utilities.
//! - **oprf**: Blinded OPRF protocol types and client/server operations.
//! - **dlog_equality**: Chaum-Pedersen proofs for discrete log equality.
//! - **ddlog_equality**: Distributed (MPC) proofs for threshold settings.
//! - **ddlog_equality_shamir**: Shamir secret sharing variant for threshold proofs.
//! - **shamir**: Shamir polynomial secret sharing over finite fields.
pub mod ddlog_equality;
pub mod ddlog_equality_shamir;
pub mod dlog_equality;
pub mod keygen;
pub mod oprf;
pub mod shamir;
