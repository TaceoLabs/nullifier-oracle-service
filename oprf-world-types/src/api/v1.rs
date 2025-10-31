//! # v1 API types
//!
//! Data transfer objects for the version 1 OPRF API.
//!
//! This module defines the request and response payloads exchanged
//! between clients and the server for the OPRF protocol, along with
//! identifiers used to reference keys and epochs. Types here wrap
//! cryptographic proofs and points with Serde (de)serialization so
//! they can be sent over the wire.

use eddsa_babyjubjub::EdDSAPublicKey;
use serde::{Deserialize, Serialize};

use crate::MerkleRoot;

/// A request sent by a client to perform an OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct OprfRequestAuth {
    /// The Merkle root associated with this request.
    pub merkle_root: MerkleRoot,
    /// The credential public key
    pub cred_pk: EdDSAPublicKey, // TODO maybe remove and get from chain
}
