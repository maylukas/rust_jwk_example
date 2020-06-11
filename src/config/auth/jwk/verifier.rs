use crate::config::auth::jwk;
use crate::config::auth::jwk::{JwkConfiguration, JwkKey};
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct Claims {
    // The audience the token was issued for
    pub aud: String,
    // The expiry date -- as epoch seconds
    pub exp: i64,
    // The token issuer
    pub iss: String,
    // The subject the token refers to
    pub sub: String,
    // Issued at -- as epoch seconds
    pub iat: i64,
}

enum VerificationError {
    InvalidAudience,
    InvalidIssuer,
    InvalidSignature,
    UnkownKeyAlgorithm,
}

pub struct JwkVerifier {
    keys: Vec<JwkKey>,
    config: JwkConfiguration,
}

impl JwkVerifier {
    pub fn new(keys: Vec<JwkKey>) -> JwkVerifier {
        JwkVerifier {
            keys: keys,
            config: jwk::get_configuration(),
        }
    }

    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let token_kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(header)) => header,
            _ => return None,
        };

        let jwk_key = match self.get_key(token_kid) {
            Some(key) => key,
            _ => return None,
        };

        let verification_result = self
            .decode_token_with_key(jwk_key, token)
            .and_then(|token| self.verify_token_data(token));

        match verification_result {
            Ok(token_data) => Some(token_data),
            _ => None,
        }
    }

    fn get_key(&self, key_id: String) -> Option<&JwkKey> {
        self.keys.iter().find(|key| key.kid == key_id)
    }

    fn decode_token_with_key(
        &self,
        key: &JwkKey,
        token: &String,
    ) -> Result<TokenData<Claims>, VerificationError> {
        let algorithm = match Algorithm::from_str(&key.alg) {
            Ok(alg) => alg,
            Err(_error) => return Err(VerificationError::UnkownKeyAlgorithm),
        };

        let key = DecodingKey::from_rsa_components(&key.n, &key.e);
        return decode::<Claims>(token, &key, &Validation::new(algorithm))
            .map_err(|_| VerificationError::InvalidSignature);
    }

    fn verify_token_data(
        &self,
        token: TokenData<Claims>,
    ) -> Result<TokenData<Claims>, VerificationError> {
        if token.claims.aud != self.config.audience {
            Result::Err(VerificationError::InvalidAudience)
        } else if token.claims.iss != self.config.issuer {
            Result::Err(VerificationError::InvalidIssuer)
        } else {
            Result::Ok(token)
        }
    }
}
