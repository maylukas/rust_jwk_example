use crate::config::auth::jwk;
use crate::config::auth::jwk::JwkConfiguration;
use serde::Deserialize;
use std::error::Error;

#[derive(Debug, Deserialize)]
struct Response {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
}

pub async fn fetch_keys_for_config(
    config: &JwkConfiguration,
) -> Result<Vec<JwkKey>, Box<dyn std::error::Error>> {
    let result = Result::Ok(
        reqwest::get(&config.jwk_url)
            .await?
            .json::<Response>()
            .await?,
    );
    return result.map(|res| res.keys);
}

pub async fn fetch_keys() -> Result<Vec<JwkKey>, Box<dyn Error>> {
    return fetch_keys_for_config(&jwk::get_configuration()).await;
}
