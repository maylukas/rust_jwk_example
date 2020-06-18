use crate::config::auth::jwk;
use crate::config::auth::jwk::use_repeating_job::use_repeating_job;
use crate::config::auth::jwk::{fetch_keys, Claims, JwkKeys, JwkVerifier};
use jsonwebtoken::TokenData;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type CleanupFn = Box<dyn Fn() -> () + Send>;

pub struct JwkAuth {
    verifier: Arc<Mutex<JwkVerifier>>,
    cleanup: Mutex<CleanupFn>,
}

impl Drop for JwkAuth {
    fn drop(&mut self) {
        // Stop the update thread when the updater is destructed
        let cleanup_fn = self.cleanup.lock().unwrap();
        cleanup_fn();
    }
}

impl JwkAuth {
    pub fn new() -> JwkAuth {
        let jwk_key_result = jwk::fetch_keys();
        let jwk_keys: JwkKeys = match jwk_key_result {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys! Cannot verify user tokens! Shutting down...")
            }
        };
        let verifier = Arc::new(Mutex::new(JwkVerifier::new(jwk_keys.keys)));

        let mut instance = JwkAuth {
            verifier: verifier,
            cleanup: Mutex::new(Box::new(|| {})),
        };

        instance.start_key_update();
        instance
    }

    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = self.verifier.lock().unwrap();
        verifier.verify(token)
    }

    fn start_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);

        let stop = use_repeating_job(move || match fetch_keys() {
            Ok(jwk_keys) => {
                let mut verifier = verifier_ref.lock().unwrap();
                verifier.set_keys(jwk_keys.keys);
                println!(
                    "Updated JWK keys. Next refresh will be in {:?}",
                    jwk_keys.validity
                );
                jwk_keys.validity
            }
            Err(_) => Duration::from_secs(10),
        });

        let mut cleanup = self.cleanup.lock().unwrap();
        *cleanup = stop;
    }
}
