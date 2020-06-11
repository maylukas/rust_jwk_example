#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use crate::config::auth::jwk::JwkKey;
use crate::config::auth::jwk::JwkVerifier;
use crate::domain::user::User;
use config::auth::jwk;
use tokio::runtime::Runtime;

pub mod config;
pub mod domain;

#[get("/user")]
fn get_user(user: User) -> String {
    user.uid
}

fn main() {
    let jwk_key_result = Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(jwk::fetch_keys());
    let jwk_keys: Vec<JwkKey> = match jwk_key_result {
        Ok(keys) => keys,
        Err(_) => panic!("Unable to fetch jwk keys! Cannot verify user tokens! Shutting down..."),
    };
    rocket::ignite()
        .manage(JwkVerifier::new(jwk_keys))
        .mount("/", routes![get_user])
        .launch();
}
