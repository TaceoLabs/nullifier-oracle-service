#![allow(clippy::too_many_arguments)]

use oprf_core::oprf::BlindedOprfResponse;
use oprf_types::api::v1::{OprfRequest, ShareIdentifier};
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::{CryptoRng, Rng};
use tracing::instrument;
use uuid::Uuid;

#[instrument(level = "debug", skip_all)]
pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_public_key: OprfPublicKey,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    mt_index: u64,
    rng: &mut R,
) -> Result<ark_babyjubjub::Fq, oprf_client::Error> {
    let request_id = Uuid::new_v4();
    let nullifier_span = tracing::Span::current();
    nullifier_span.record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let query_hash =
        oprf_core::oprf::client::generate_query(mt_index.into(), oprf_key_id.into(), action);
    let (blinded_request, blinding_factor) = oprf_core::oprf::client::blind_query(query_hash, rng);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        share_identifier: ShareIdentifier {
            oprf_key_id,
            share_epoch,
        },
        auth: (),
    };

    let (challenge, _dlog_proof) = oprf_client::distributed_oprf(
        request_id,
        oprf_public_key,
        services,
        threshold,
        oprf_req,
        &blinded_request,
    )
    .await?;

    let blinded_response = challenge.blinded_response();
    let blinding_factor_prepared = blinding_factor.prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

    let poseidon_nullifier = poseidon2::bn254::t4::permutation(&[
        oprf_core::oprf::client::get_oprf_ds(),
        query_hash,
        unblinded_response.x,
        unblinded_response.y,
    ]);

    let nullifier = poseidon_nullifier[1];

    Ok(nullifier)
}
