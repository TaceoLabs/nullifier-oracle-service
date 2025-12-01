use ark_ff::UniformRand as _;
use oprf_types::crypto::OprfPublicKey;
use oprf_types::{OprfKeyId, ShareEpoch};
use rand::{CryptoRng, Rng};
use tracing::instrument;

#[instrument(level = "debug", skip_all)]
pub async fn distributed_oprf<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_public_key: OprfPublicKey,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    action: ark_babyjubjub::Fq,
    rng: &mut R,
) -> Result<ark_babyjubjub::Fq, oprf_client::Error> {
    let query = action;
    let blinding_factor = ark_babyjubjub::Fr::rand(rng);
    let auth = ();

    let verifiable_oprf_output = oprf_client::distributed_oprf(
        services,
        threshold,
        oprf_public_key,
        oprf_key_id,
        share_epoch,
        query,
        blinding_factor,
        auth,
    )
    .await?;

    Ok(verifiable_oprf_output.output)
}
