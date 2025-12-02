use ark_ff::PrimeField as _;
use oprf_client::{BlindingFactor, Connector};
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::{CryptoRng, Rng};
use tracing::instrument;

#[instrument(level = "debug", skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn distributed_oprf<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_public_key: OprfPublicKey,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> Result<ark_babyjubjub::Fq, oprf_client::Error> {
    let query = action;
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF");
    let auth = ();

    let verifiable_oprf_output = oprf_client::distributed_oprf(
        services,
        threshold,
        oprf_public_key,
        oprf_key_id,
        share_epoch,
        query,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await?;

    Ok(verifiable_oprf_output.output)
}
