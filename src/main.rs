#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use crate::config::auth::jwk::JwkAuth;
use crate::domain::user::User;

pub mod config;
pub mod domain;

#[get("/user")]
fn get_user(user: User) -> String {
    user.uid
}

fn main() {
    rocket::ignite()
        .manage(JwkAuth::new())
        .mount("/", routes![get_user])
        .launch();
}
