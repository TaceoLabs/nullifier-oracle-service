use alloy::network::EthereumWallet;
use clap::Parser;
use eyre::Context;
use oprf_client::Connector;
use oprf_test::oprf_key_registry_scripts;
use oprf_types::{OprfKeyId, ShareEpoch, crypto::OprfPublicKey};
use secrecy::ExposeSecret;
use std::time::Instant;
use tokio::task::JoinSet;

use crate::{OprfDevClientConfig, run_nullifier};

#[derive(Clone, Parser, Debug)]
pub struct EndlessRunCommand {
    /// The amount of nullifiers to generate
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub oprf_per_epoch: usize,

    /// How many epochs should we do until we are finished.
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub iterations: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn endless_run(
    config: OprfDevClientConfig,
    oprf_key_id: OprfKeyId,
    wallet: EthereumWallet,
    oprf_public_key: OprfPublicKey,
    endless_run_cmd: EndlessRunCommand,
    connector: Connector,
) -> eyre::Result<()> {
    let mut epoch = ShareEpoch::from(config.start_epoch);
    let EndlessRunCommand {
        oprf_per_epoch,
        iterations,
    } = endless_run_cmd;
    let iterations = iterations.unwrap_or(usize::MAX);
    for run in 0..endless_run_cmd.iterations.unwrap_or(usize::MAX) {
        if iterations == usize::MAX {
            tracing::info!("doing run {run}..");
        } else {
            tracing::info!("doing run {run}/{iterations}..");
        }
        let instant = Instant::now();
        let mut runs = (0..oprf_per_epoch)
            .map(|_| {
                let connector = connector.clone();
                let nodes = config.services.clone();
                let use_last_epoch = rand::random::<bool>();
                let tested_epoch = if use_last_epoch { epoch.prev() } else { epoch };
                async move {
                    run_nullifier(
                        nodes,
                        tested_epoch,
                        config.threshold,
                        oprf_key_id,
                        oprf_public_key,
                        connector,
                    )
                    .await
                }
            })
            .collect::<JoinSet<_>>();
        let mut counter = 0;
        while let Some(result) = runs.join_next().await {
            result
                .context("could not join")?
                .context("while doing nullifier run")?;
            tracing::debug!("oprf {counter}/{oprf_per_epoch}...");
            counter += 1;
        }
        let elapsed = instant.elapsed();
        tracing::info!("took {elapsed:?} - init reshare..");
        epoch = epoch.next();
        oprf_key_registry_scripts::init_reshare(
            oprf_key_id,
            config.chain_rpc_url.expose_secret(),
            config.oprf_key_registry_contract,
            config.taceo_private_key.expose_secret(),
        );
        let new_key =
            super::fetch_oprf_public_key_by_epoch(oprf_key_id, epoch, &wallet, &config).await?;
        assert_eq!(new_key, oprf_public_key);
    }
    Ok(())
}
