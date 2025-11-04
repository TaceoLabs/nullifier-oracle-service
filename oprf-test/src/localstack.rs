use aws_config::Region;
use aws_sdk_secretsmanager::{
    config::Credentials,
    types::{Filter, FilterNameStringType},
};

pub async fn client() -> aws_sdk_secretsmanager::Client {
    let region_provider = Region::new("us-east-1");
    let credentials = Credentials::new("test", "test", None, None, "Static");
    // use TEST_AWS_ENDPOINT_URL if set in testcontainer
    let aws_config = aws_config::from_env()
        .region(region_provider)
        .endpoint_url(std::env::var("TEST_AWS_ENDPOINT_URL").expect("TEST_AWS_ENDPOINT_URL is set"))
        .credentials_provider(credentials)
        .load()
        .await;
    aws_sdk_secretsmanager::Client::new(&aws_config)
}

pub async fn load_secret(
    client: aws_sdk_secretsmanager::Client,
    secret_id: String,
) -> eyre::Result<String> {
    let secret = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await?
        .secret_string()
        .ok_or_else(|| eyre::eyre!("is not a secret-string"))?
        .to_owned();
    Ok(secret)
}

pub async fn list_secrets(
    client: aws_sdk_secretsmanager::Client,
    secret_id_prefix: &str,
) -> eyre::Result<Vec<String>> {
    let mut next_token = None;
    let mut secret_ids = Vec::new();
    loop {
        let secrets = client
            .list_secrets()
            .set_next_token(next_token)
            .filters(
                Filter::builder()
                    .key(FilterNameStringType::Name)
                    .values(secret_id_prefix)
                    .build(),
            )
            .send()
            .await?;
        secret_ids.extend(
            secrets
                .secret_list()
                .iter()
                .map(|secret| secret.name().expect("has a name").to_string()),
        );
        next_token = secrets.next_token;
        if next_token.is_none() {
            break;
        }
    }
    Ok(secret_ids)
}
