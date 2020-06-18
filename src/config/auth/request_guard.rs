use crate::config::auth::jwk::JwkAuth;
use crate::domain::user::User;
use rocket::http::Status;
use rocket::request;
use rocket::request::FromRequest;
use rocket::Outcome;
use rocket::Request;
use rocket::State;

#[derive(Debug)]
pub enum AuthError {
    InvalidJwt,
    NoAuthorizationHeader,
    MultipleKeysProvided,
    NoJwkVerifier,
}

fn get_token_from_header(header: &str) -> Option<String> {
    let prefix_len = "Bearer ".len();

    match header.len() {
        l if l < prefix_len => None,
        _ => Some(header[prefix_len..].to_string()),
    }
}

fn verify_token(token: &String, auth: &JwkAuth) -> request::Outcome<User, AuthError> {
    let verified_token = auth.verify(&token);
    let maybe_user = verified_token.map(|token| User {
        uid: token.claims.sub,
    });
    match maybe_user {
        Some(user) => Outcome::Success(user),
        None => Outcome::Failure((Status::BadRequest, AuthError::InvalidJwt)),
    }
}

fn parse_and_verify_auth_header(header: &str, auth: &JwkAuth) -> request::Outcome<User, AuthError> {
    let maybe_token = get_token_from_header(header);

    match maybe_token {
        Some(token) => verify_token(&token, auth),
        None => Outcome::Failure((Status::Unauthorized, AuthError::InvalidJwt)),
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = AuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let auth_headers: Vec<_> = request.headers().get("Authorization").collect();
        let configured_auth = request.guard::<State<JwkAuth>>();

        match configured_auth {
            Outcome::Success(auth) => match auth_headers.len() {
                0 => Outcome::Failure((Status::Unauthorized, AuthError::NoAuthorizationHeader)),
                1 => parse_and_verify_auth_header(auth_headers[0], &auth),
                _ => Outcome::Failure((Status::BadRequest, AuthError::MultipleKeysProvided)),
            },
            _ => Outcome::Failure((Status::InternalServerError, AuthError::NoJwkVerifier)),
        }
    }
}

#[cfg(test)]
mod describe {
    #[test]
    fn test_extract_token() {
        let token = super::get_token_from_header("Bearer token_string");
        assert_eq!(Some("token_string".to_string()), token)
    }

    #[test]
    fn test_extract_token_too_short() {
        assert_eq!(None, super::get_token_from_header(&"Bear".to_string()));
        assert_eq!(None, super::get_token_from_header(&"Bearer".to_string()))
    }
}
