use oprf_core::ddlog_equality::PartialDLogEqualityCommitments;
use oprf_core::oprf::{BlindedOPrfRequest, OprfClient};

use ark_ec::AffineRepr;
use ark_serde_compat::groth16::Groth16Proof;
use oprf_core::shamir;
use oprf_core::{
    ddlog_equality::DLogEqualityChallenge,
    proof_input_gen::{nullifier::NullifierProofInput, query::QueryProofInput},
};
use oprf_types::api::v1::{
    ChallengeRequest, ChallengeResponse, NullifierShareIdentifier, OprfRequest, OprfResponse,
};
use oprf_types::crypto::{PartyId, RpNullifierKey};
use rand::{CryptoRng, Rng};
use uuid::Uuid;

pub use circom_types;
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
pub use groth16;
pub use oprf_core::proof_input_gen::query::MAX_PUBLIC_KEYS;

use crate::zk::{Groth16Error, Groth16Material};

pub mod nonblocking;
mod types;
pub mod zk;

pub use types::CredentialsSignature;
pub use types::MerkleMembership;
pub use types::OprfQuery;
pub use types::UserKeyMaterial;

pub const MAX_DEPTH: usize = 30;

pub type ScalarField = ark_babyjubjub::Fr;
pub type BaseField = ark_babyjubjub::Fq;
pub type Affine = ark_babyjubjub::EdwardsAffine;
pub type Projective = ark_babyjubjub::EdwardsProjective;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ApiError(#[from] reqwest::Error),
    #[error("expected degree {threshold} responses, got {n}")]
    NotEnoughOprfResponses { n: usize, threshold: usize },
    #[error("prove could not be verified")]
    InvalidProof,
    #[error("invalid merkle length, expected {expected}, but is {is}")]
    InvalidSiblingsLength { expected: usize, is: usize },
    #[error("DLog prove could not be verified")]
    InvalidDLogProof,
    #[error("Index in public-key batch must be in range [0..6], but is {0}")]
    InvalidPublicKeyIndex(u64),
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

pub struct SignedOprfQuery {
    request_id: Uuid,
    oprf_request: OprfRequest,
    query: OprfQuery,
    groth16_material: Groth16Material,
    blinded_request: BlindedOPrfRequest,
    query_proof_input: QueryProofInput<MAX_DEPTH>,
    query_hash: BaseField,
}

pub struct OprfSessions {
    services: Vec<String>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogEqualityCommitments>,
}

pub struct Challenges {
    request_id: Uuid,
    challenge_request: ChallengeRequest,
    lagrange: Vec<ScalarField>,
    blinded_request: BlindedOPrfRequest,
    groth16_material: Groth16Material,
    blinded_response: Affine,
    query_proof_input: QueryProofInput<MAX_DEPTH>,
    query_hash: BaseField,
    rp_nullifier_key: RpNullifierKey,
}

pub struct NullifierArgs {
    pub credential_signature: CredentialsSignature,
    pub merkle_membership: MerkleMembership,
    pub query: OprfQuery,
    pub groth16_material: Groth16Material,
    pub key_material: UserKeyMaterial,
    pub rp_nullifier_key: RpNullifierKey,
    pub signal_hash: BaseField,
    pub id_commitment_r: BaseField,
}

pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    args: NullifierArgs,
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<BaseField>, BaseField)> {
    let NullifierArgs {
        credential_signature,
        merkle_membership,
        query,
        groth16_material,
        key_material,
        signal_hash,
        id_commitment_r,
        rp_nullifier_key,
    } = args;

    let signed_query = sign_oprf_query(
        credential_signature,
        merkle_membership,
        groth16_material,
        query,
        key_material,
        rng,
    )?;

    let req = signed_query.get_request();
    let sessions = nonblocking::init_sessions(services, threshold, req).await?;

    let challenges = compute_challenges(signed_query, &sessions, rp_nullifier_key)?;
    let req = challenges.get_request();
    let responses = nonblocking::finish_sessions(sessions, req).await?;
    verify_challenges(challenges, responses, signal_hash, id_commitment_r, rng)
}

impl Challenges {
    pub fn get_request(&self) -> ChallengeRequest {
        self.challenge_request.clone()
    }
}

impl OprfSessions {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            services: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, service: String, response: OprfResponse) {
        self.services.push(service);
        self.party_ids.push(response.party_id);
        self.commitments.push(response.commitments);
    }

    fn len(&self) -> usize {
        self.services.len()
    }
}

impl SignedOprfQuery {
    pub fn get_request(&self) -> OprfRequest {
        self.oprf_request.clone()
    }
}

pub fn compute_challenges(
    query: SignedOprfQuery,
    sessions: &OprfSessions,
    rp_nullifier_key: RpNullifierKey,
) -> Result<Challenges> {
    let coeffs = sessions
        .party_ids
        .iter()
        .map(|id| usize::from(id.into_inner() + 1))
        .collect::<Vec<_>>();
    let lagrange = shamir::lagrange_from_coeff(&coeffs);
    let (blinded_response, challenge) =
        DLogEqualityChallenge::combine_commitments_and_create_challenge_shamir(
            &sessions.commitments,
            &lagrange,
            rp_nullifier_key.inner(),
            query.blinded_request.blinded_query(),
        );
    Ok(Challenges {
        groth16_material: query.groth16_material,
        query_proof_input: query.query_proof_input,
        query_hash: query.query_hash,
        request_id: query.request_id,
        lagrange,
        blinded_request: query.blinded_request,
        blinded_response,
        rp_nullifier_key,
        challenge_request: ChallengeRequest {
            request_id: query.request_id,
            challenge,
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.query.rp_id,
                share_epoch: query.query.share_epoch,
            },
        },
    })
}

pub fn sign_oprf_query<R: Rng + CryptoRng>(
    credentials_signature: CredentialsSignature,
    merkle_membership: MerkleMembership,
    groth16_material: Groth16Material,
    query: OprfQuery,
    key_material: UserKeyMaterial,
    rng: &mut R,
) -> Result<SignedOprfQuery> {
    if merkle_membership.siblings.len() != MAX_DEPTH {
        return Err(Error::InvalidSiblingsLength {
            expected: MAX_DEPTH,
            is: merkle_membership.siblings.len(),
        });
    }
    if key_material.pk_index >= MAX_PUBLIC_KEYS as u64 {
        return Err(Error::InvalidPublicKeyIndex(key_material.pk_index));
    }

    let request_id = Uuid::new_v4();

    let query_hash = OprfClient::generate_query(
        merkle_membership.mt_index.into(),
        query.rp_id.into_inner().into(),
        query.action,
    );
    let oprf_client = OprfClient::new(key_material.public_key());
    let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, query_hash, rng);
    let signature = key_material.sk.sign(blinding_factor.query());

    let query_input = QueryProofInput::<MAX_DEPTH> {
        pk: key_material.pk_batch.into_proof_input(),
        pk_index: key_material.pk_index.into(),
        s: signature.s,
        r: [signature.r.x, signature.r.y],
        cred_type_id: credentials_signature.type_id,
        cred_pk: [
            credentials_signature.issuer.pk.x,
            credentials_signature.issuer.pk.y,
        ],
        cred_hashes: credentials_signature.hashes,
        cred_genesis_issued_at: credentials_signature.genesis_issued_at.into(),
        cred_expires_at: credentials_signature.expires_at.into(),
        cred_s: credentials_signature.signature.s,
        cred_r: [
            credentials_signature.signature.r.x,
            credentials_signature.signature.r.y,
        ],
        current_time_stamp: query.current_time_stamp.into(),
        merkle_root: merkle_membership.root.into_inner(),
        depth: merkle_membership.depth.into(),
        mt_index: merkle_membership.mt_index.into(),
        siblings: merkle_membership
            .siblings
            .try_into()
            .expect("checked in init step"),
        beta: blinding_factor.beta(),
        rp_id: query.rp_id.into_inner().into(),
        action: query.action,
        nonce: query.nonce,
        q: blinded_request.blinded_query_as_public_output(),
    };

    let (proof, _) = groth16_material.generate_query_proof(&query_input, rng)?;
    Ok(SignedOprfQuery {
        request_id,
        groth16_material,
        query_hash,
        query_proof_input: query_input,
        oprf_request: OprfRequest {
            request_id,
            proof,
            point_b: blinded_request.blinded_query(),
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.rp_id,
                share_epoch: query.share_epoch,
            },
            merkle_epoch: merkle_membership.epoch,
            action: query.action,
            nonce: query.nonce,
            signature: query.nonce_signature,
            cred_pk: credentials_signature.issuer,
            current_time_stamp: query.current_time_stamp,
            merkle_depth: merkle_membership.depth,
        },
        blinded_request,
        query,
    })
}

pub fn verify_challenges<R: Rng + CryptoRng>(
    challenges: Challenges,
    responses: Vec<ChallengeResponse>,
    signal_hash: BaseField,
    id_commitment_r: BaseField,
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<BaseField>, BaseField)> {
    let proofs = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();
    let dlog_proof = challenges
        .challenge_request
        .challenge
        .combine_proofs_shamir(&proofs, &challenges.lagrange);
    if !dlog_proof.verify(
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_request.blinded_query(),
        challenges.blinded_response,
        Affine::generator(),
    ) {
        return Err(Error::InvalidDLogProof);
    }

    let nullifier_input = NullifierProofInput::new(
        challenges.request_id,
        challenges.rp_nullifier_key.inner(),
        signal_hash,
        challenges.query_proof_input,
        challenges.query_hash,
        challenges.blinded_response,
        dlog_proof,
        id_commitment_r,
    );
    let (proof, public) = challenges
        .groth16_material
        .generate_nullifier_proof(&nullifier_input, rng)?;
    Ok((proof, public, nullifier_input.nullifier))
}
