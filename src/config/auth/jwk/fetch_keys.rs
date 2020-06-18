use crate::config::auth::jwk;
use crate::config::auth::jwk::get_max_age::get_max_age;
use crate::config::auth::jwk::JwkConfiguration;
use serde::Deserialize;
use std::error::Error;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
}

pub struct JwkKeys {
    pub keys: Vec<JwkKey>,
    pub validity: Duration,
}

const FALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

pub fn fetch_keys_for_config(
    config: &JwkConfiguration,
) -> Result<JwkKeys, Box<dyn std::error::Error>> {
    let http_response = reqwest::blocking::get(&config.jwk_url)?;
    let max_age = get_max_age(&http_response).unwrap_or(FALLBACK_TIMEOUT);
    let result = Result::Ok(http_response.json::<KeyResponse>()?);

    return result.map(|res| JwkKeys {
        keys: res.keys,
        validity: max_age,
    });
}

pub fn fetch_keys() -> Result<JwkKeys, Box<dyn Error>> {
    return fetch_keys_for_config(&jwk::get_configuration());
}
