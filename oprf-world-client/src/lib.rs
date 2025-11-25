#![allow(clippy::too_many_arguments)]

use std::io::Read;
use std::path::Path;

use circom_types::ark_bn254::Bn254;
use circom_types::groth16::Proof;
use oprf_core::ddlog_equality::shamir::DLogCommitmentsShamir;
use oprf_core::dlog_equality::DLogEqualityProof;
use oprf_core::oprf::{self, BlindedOprfRequest, BlindingFactor};

use groth16_material::Groth16Error;
use oprf_types::api::v1::{OprfRequest, ShareIdentifier};
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use oprf_world_types::api::v1::OprfRequestAuth;
use oprf_world_types::proof_inputs::nullifier::NullifierProofInput;
use oprf_world_types::proof_inputs::query::{MAX_PUBLIC_KEYS, QueryProofInput};
use oprf_world_types::{CredentialsSignature, MerkleMembership, TREE_DEPTH, UserKeyMaterial};
use rand::{CryptoRng, Rng};

pub use groth16;

const QUERY_GRAPH_BYTES: &[u8] = include_bytes!("../../circom/main/query/OPRFQueryGraph.bin");
const NULLIFIER_GRAPH_BYTES: &[u8] =
    include_bytes!("../../circom/main/nullifier/OPRFNullifierGraph.bin");

#[cfg(feature = "embed-zkeys")]
const QUERY_ZKEY_BYTES: &[u8] = include_bytes!("../../circom/main/query/OPRFQuery.arks.zkey");
#[cfg(feature = "embed-zkeys")]
const NULLIFIER_ZKEY_BYTES: &[u8] =
    include_bytes!("../../circom/main/nullifier/OPRFNullifier.arks.zkey");

/// The SHA-256 fingerprint of the OPRFQuery ZKey.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "50386ea28e3c8cd01fe59ab68e7ecd0a6b8b07d3b8ad6460c04a430ef5c2121f";
/// The SHA-256 fingerprint of the OPRFNullifier ZKey.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "bb1301f25cbe8d624a227c5f0875fa5dec9501c09357d82b49f59ee73505e94d";

/// The SHA-256 fingerprint of the OPRFQuery witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "1016fc75f79a872a33ec0537c074857c6750c21f7e2e4e2a34acbbad5d0997b3";
/// The SHA-256 fingerprint of the OPRFNullifier witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "87756ce49e17f89e28b963d53e1fd55e17f9a2b413b7630632241a9a03af663a";

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};
use tracing::instrument;
use uuid::Uuid;

/// Arguments required to generate a nullifier proof.
///
/// This struct bundles all inputs needed for [`nullifier`] to produce a
/// Groth16 nullifier proof. Users typically construct this from their
/// credentials, key material, and query context.
pub struct NullifierArgs {
    /// Signature over the user's credentials.
    pub credentials_signature: CredentialsSignature,
    /// Merkle membership proof of the user's credential in the registry.
    pub merkle_membership: MerkleMembership,
    /// The original OPRF query (RP ID, action, nonce, timestamp, etc.).
    pub query: OprfQuery,
    /// User's key material (private and public keys, batch index, etc.).
    pub key_material: UserKeyMaterial,
    /// The OPRF public-key.
    pub oprf_public_key: OprfPublicKey,
    /// Signal hash as in semaphore
    pub signal_hash: ark_babyjubjub::Fq,
    /// Commitment to the id
    pub id_commitment_r: ark_babyjubjub::Fq,
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the embedded keys in the binary.
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_nullifier_material() -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_bytes(NULLIFIER_ZKEY_BYTES, NULLIFIER_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the query proof from the embedded keys in the binary.
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_query_material() -> CircomGroth16Material {
    build_query_builder()
        .build_from_bytes(QUERY_ZKEY_BYTES, QUERY_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided reader.
pub fn load_nullifier_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_nullifier_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the query proof from the provided reader.
pub fn load_query_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided path.
pub fn load_nullifier_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_paths(zkey, graph)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided path.
pub fn load_query_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_paths(zkey, graph)?)
}

fn build_nullifier_builder() -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(NULLIFIER_ZKEY_FINGERPRINT.into())
        .fingerprint_graph(NULLIFIER_GRAPH_FINGERPRINT.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
}

fn build_query_builder() -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(QUERY_ZKEY_FINGERPRINT.into())
        .fingerprint_graph(QUERY_GRAPH_FINGERPRINT.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
}

#[instrument(level="debug", skip_all, fields(request_id=tracing::field::Empty))]
pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    query_material: &CircomGroth16Material,
    nullifier_material: &CircomGroth16Material,
    args: NullifierArgs,
    rng: &mut R,
) -> Result<VerifiableNullifier, WorldIdNullifierError> {
    let NullifierArgs {
        credentials_signature,
        merkle_membership,
        query,
        key_material,
        oprf_public_key,
        signal_hash,
        id_commitment_r,
    } = args;

    let request_id = Uuid::new_v4();
    let nullifier_span = tracing::Span::current();
    nullifier_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let signed_query = sign_oprf_query(
        credentials_signature,
        merkle_membership,
        query_material,
        query,
        key_material,
        request_id,
        rng,
    )?;

    let (challenge, dlog_proof) = oprf_client::distributed_oprf(
        request_id,
        oprf_public_key,
        services,
        threshold,
        signed_query.get_request(),
        &signed_query.blinded_request,
    )
    .await?;

    compute_oprf_output(
        oprf_public_key,
        dlog_proof,
        challenge,
        signed_query,
        signal_hash,
        id_commitment_r,
        nullifier_material,
        rng,
    )
}

/// The basic request a client sends to the OPRF service.
///
/// It contains the OPRF public-key id, the share epoch, the action
/// the user wants to compute a nullifier for, and a fresh nonce.
/// The RP signs `(nonce || timestamp)` (both in little-endian byte encoding)
/// to prevent replay. That signature is included here.
#[derive(Clone)]
pub struct OprfQuery {
    /// ID of OPRF public-key
    pub oprf_key_id: OprfKeyId,
    /// Epoch of the key.
    pub share_epoch: ShareEpoch,
    /// The action the user wants to compute a nullifier for.
    pub action: ark_babyjubjub::Fq,
    /// The nonce obtained from the RP.
    pub nonce: ark_babyjubjub::Fq,
    /// The timestamp obtained from the RP.
    pub current_time_stamp: u64,
    /// The RP's signature over `(nonce || timestamp)`.
    pub nonce_signature: k256::ecdsa::Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum WorldIdNullifierError {
    /// Provided public key index is out of valid range.
    #[error("Index in public-key batch must be in range [0..6], but is {0}")]
    InvalidPublicKeyIndex(u64),

    #[error(transparent)]
    OprfError(#[from] oprf_client::Error),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
}

#[derive(Clone)]
pub struct SignedOprfQuery {
    oprf_request: OprfRequest<OprfRequestAuth>,
    pub blinded_request: BlindedOprfRequest,
    query_input: QueryProofInput<TREE_DEPTH>,
    blinding_factor: BlindingFactor,
}

pub struct VerifiableNullifier {
    pub proof: Proof<Bn254>,
    pub public_input: Vec<ark_babyjubjub::Fq>,
    pub nullifier: ark_babyjubjub::Fq,
    pub id_commitment: ark_babyjubjub::Fq,
}

impl SignedOprfQuery {
    /// Returns the [`OprfRequest`] for this signed query.
    pub fn get_request(&self) -> OprfRequest<OprfRequestAuth> {
        self.oprf_request.clone()
    }
}

pub fn sign_oprf_query<R: Rng + CryptoRng>(
    credentials_signature: CredentialsSignature,
    merkle_membership: MerkleMembership,
    query_material: &CircomGroth16Material,
    query: OprfQuery,
    key_material: UserKeyMaterial,
    request_id: Uuid,
    rng: &mut R,
) -> Result<SignedOprfQuery, WorldIdNullifierError> {
    if key_material.pk_index >= MAX_PUBLIC_KEYS as u64 {
        return Err(WorldIdNullifierError::InvalidPublicKeyIndex(
            key_material.pk_index,
        ));
    }

    let query_hash = oprf::client::generate_query(
        merkle_membership.mt_index.into(),
        query.oprf_key_id.into(),
        query.action,
    );
    let (blinded_request, blinding_factor) = oprf::client::blind_query(query_hash, rng);
    let signature = key_material.sk.sign(blinding_factor.query());

    let query_input = QueryProofInput::<TREE_DEPTH> {
        pk: key_material.pk_batch.into_inner(),
        pk_index: key_material.pk_index.into(),
        s: signature.s,
        r: signature.r,
        cred_type_id: credentials_signature.type_id,
        cred_pk: credentials_signature.issuer.pk,
        cred_hashes: credentials_signature.hashes,
        cred_genesis_issued_at: credentials_signature.genesis_issued_at.into(),
        cred_expires_at: credentials_signature.expires_at.into(),
        cred_s: credentials_signature.signature.s,
        cred_r: credentials_signature.signature.r,
        current_time_stamp: query.current_time_stamp.into(),
        merkle_root: merkle_membership.root.into_inner(),
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: merkle_membership.mt_index.into(),
        siblings: merkle_membership.siblings,
        beta: blinding_factor.beta(),
        rp_id: query.oprf_key_id.into(),
        action: query.action,
        nonce: query.nonce,
    };

    tracing::debug!("generate query proof");
    let (proof, _) = query_material.generate_proof(&query_input, rng)?;

    Ok(SignedOprfQuery {
        blinding_factor,
        query_input,
        oprf_request: OprfRequest {
            request_id,
            blinded_query: blinded_request.blinded_query(),
            share_identifier: ShareIdentifier {
                oprf_key_id: query.oprf_key_id,
                share_epoch: query.share_epoch,
            },
            auth: OprfRequestAuth {
                proof: proof.into(),
                action: query.action,
                nonce: query.nonce,
                merkle_root: merkle_membership.root,
                cred_pk: credentials_signature.issuer,
                current_time_stamp: query.current_time_stamp,
                signature: query.nonce_signature,
            },
        },
        blinded_request,
    })
}

pub fn compute_oprf_output<R: Rng + CryptoRng>(
    oprf_public_key: OprfPublicKey,
    dlog_proof: DLogEqualityProof,
    challenge: DLogCommitmentsShamir,
    signed_query: SignedOprfQuery,
    signal_hash: ark_babyjubjub::Fq,
    id_commitment_r: ark_babyjubjub::Fq,
    nullifier_material: &CircomGroth16Material,
    rng: &mut R,
) -> Result<VerifiableNullifier, WorldIdNullifierError> {
    let nullifier_input = NullifierProofInput::new(
        signed_query.query_input,
        dlog_proof,
        oprf_public_key.inner(),
        challenge.blinded_response(),
        signal_hash,
        id_commitment_r,
        signed_query.blinding_factor,
    );

    tracing::debug!("generate nullifier proof");
    let (proof, public_input) = nullifier_material.generate_proof(&nullifier_input, rng)?;

    // 2 outputs, 0 is id_commitment, 1 is nullifier
    let id_commitment = public_input[0];
    let nullifier = public_input[1];
    Ok(VerifiableNullifier {
        proof: proof.into(),
        public_input,
        nullifier,
        id_commitment,
    })
}
