use jwk_example::fetch_keys_for_config;
use jwk_example::JwkConfiguration;
use jwk_example::JwkKey;

fn assert_is_valid_key(key: &JwkKey) {
    assert!(key.kid.len() > 0);
    assert!(key.n.len() > 0);
    assert!(key.e.len() > 0);
    assert!(key.kty.len() > 0);
    assert!(key.alg.len() > 0);
}

#[tokio::test]
async fn test_fetch_keys() {
    let config = JwkConfiguration {
        jwk_url: String::from("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"),
        audience: String::from("tracking-app-dev-271418"),
        issuer: String::from("https://securetoken.google.com/tracking-app-dev-271418")
    };
    let result = fetch_keys_for_config(&config)
        .await
        .expect("Did not fetch keys");
    assert_eq!(2, result.len());
    assert_is_valid_key(result.get(0).expect(""));
    assert_is_valid_key(result.get(1).expect(""));
}
