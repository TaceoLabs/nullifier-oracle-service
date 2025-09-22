#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_nullifier() -> eyre::Result<()> {
    let oprf_services = oprf_test::start_services().await;
    let mut rng = rand::thread_rng();
    let args = oprf_test::nullifier_args(&mut rng);
    let (_proof, _nullifier) = oprf_client::nullifier(&oprf_services, args, &mut rng).await?;
    Ok(())
}
