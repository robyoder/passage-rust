#![warn(missing_docs)]
//!
//! This crate provides a library for working with [Passage](https://passage.id), a modern passwordless authentication experience based on passkeys and magic links. This library currently implements a very small subset of the available Passage API endpoints.
//!
//! See Passage [Authentication API](https://docs.passage.id/api-docs/authentication-api) and [Management API](https://docs.passage.id/api-docs/management-api)  for all the possible endpoints that could be added to this crate in the future.
//!
//! ## Usage
//!
//! This crate is on [crates.io](https://crates.io/crates/passage-id) and can be used by adding `passage-id` to your dependencies in your project's Cargo.toml.
//!
//! ```toml
//! [dependencies]
//! passage-id = "latest"
//! ```
//!
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;

/// Passage is the main entry point you'll be working with. Create with [Passage::new].
pub struct Passage {
    app_id: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
}

/// The error type for possible authentication failures when validating a JWT.
#[derive(Debug, PartialEq)]
pub enum AuthError {
    /// Failed to decode the Passage auth token (e.g. the `psg_auth_token` cookie value)
    TokenHeaderDecoding(jwt::errors::Error),

    /// Key ids mismatched between public JWK and Passage auth token
    KidMismatch(Option<String>, Option<String>),

    /// Failed to parse the provided public JWK
    PubKeyParsing(String),

    /// Failed to decode the JWT. See associated `jwt::errors::Error` for details.
    TokenDecoding(jwt::errors::Error),
}

impl Passage {
    /// Creates a new [Passage] for interacting with the Passage API. Your `app_id` can be found in the [Passage console](https://console.passage.id).
    pub fn new(app_id: String) -> Self {
        Passage { app_id }
    }

    /// Verify the Passage authentication token. When successful, the resulting String is the `passage_id` for the logged in user. See [Validation Passage JWTs](https://docs.passage.id/backend/overview/other#validation-passage-jwts) for details.
    ///
    /// ```rust
    /// // Your app id from https://console.passage.id/settings
    /// let app_id = "cHxJnV5eqc8aIrgQjgfIEsMl";
    ///
    /// // Your app's public JWK from https://auth.passage.id/v1/apps/{app_id}/.well-known/jwks.json. You only want the key itself, not the array.
    /// let pub_key = r#"{
    ///     "alg": "RS256",
    ///     "kty": "RSA",
    ///     "use": "sig",
    ///     "n": "...",
    ///     "e": "AQAB",
    ///     "kid": "..."
    ///   }"#;
    ///
    /// // If you are using an Element, the Passage authentication JWT will be sent to your application via a cookie with the key `psg_auth_token`
    /// let psg_auth_token = "...";
    ///
    /// let passage = Passage::new(String::from(app_id));
    /// let result = passage.authenticate_token(psg_auth_token, pub_key);
    ///
    /// match result {
    ///     Ok(passage_user_id) => println!(
    ///         "Passage JWT is valid. passage_user_id=<{}>",
    ///         passage_user_id
    ///     ),
    ///     Err(err) => {
    ///         println!("Auth error: {:?}", err);
    ///     }
    /// }
    /// ```
    pub fn authenticate_token(self, token: &str, pub_jwk: &str) -> Result<String, AuthError> {
        let key = pub_jwk
            .parse::<jwk::JsonWebKey>()
            .map_err(|e| AuthError::PubKeyParsing(e.to_string()))?;

        let header = jwt::decode_header(token).map_err(AuthError::TokenHeaderDecoding)?;

        if header.kid != key.key_id {
            return Err(AuthError::KidMismatch(header.kid, key.key_id));
        }

        let expected_iss = String::from("https://auth.passage.id/v1/apps/") + &self.app_id;
        let mut validation = jwt::Validation::new(jwt::Algorithm::RS256);
        validation
            .required_spec_claims
            .extend(["exp", "iss", "nbf", "sub"].into_iter().map(String::from));
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;
        validation.set_issuer(&[expected_iss]);

        let token = jwt::decode::<Claims>(&token, &key.key.to_decoding_key(), &validation)
            .map_err(AuthError::TokenDecoding)?;

        Ok(token.claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_passage() {
        let passage = Passage::new(String::from("test"));
        assert_eq!(passage.app_id, String::from("test"));
    }

    // Generated using https://mkjwk.org/
    const PUB_JWK: &'static str = r#"{
        "kty": "RSA",
        "e": "AQAB",
        "use": "sig",
        "kid": "r50vKukJl4oVaT78O0ELIGS4w8ynMY_4lRSBq-uvTX4",
        "alg": "RS256",
        "n": "rJGYlYJPZZmeZUyxtEdbbzyMZrBbJPMbhkaioazk6_43d9SIYcVWouei6R5WXQrO6chx3HaSUOqRcYv4oF9x6FVrBWSGyxbzjltcnwKOWn3K8qmJWQvv2nLvLJvf_wdUR2IlH2SfGEE9Om6mJG6tw4Hvn0FauCvnS_a5E5oi0-Mp8rDK3KaHKTr7YHPNzKZzYryF8Ids2mb7PULxFNErIUmB6yTuxUjmbLXwRK2nHe2gHnaepYqcTZIQcTgfS8NeAqKUHWwRkvqmi_pIr9g8azwCqQ8cHpaOoxyUtTlSva1ggkiinJdeIP1-RF-ElflqGtqLXF9OJc8Kcd1ivIaEaQ"
    }"#;

    #[test]
    fn authenticate_good_token() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UiLCJleHAiOjIwMDAwMDAwMDB9.hPDcPU5Y84MTiQZ9uZ0aJqxzLEBQiD9F2xWeZINGIKbwehHudExV0MoqoLxHnpUcGIKPIaW0FjCDCZcJA2dGoLC6n-X8l7qUgMJBbbCIEtNhQNMe4AIlEpsmk3t83WNXSQVeh2fKBAJ1X_oad1RRNuQUgCam6MMJx8m3AozPBAXcGjS6D_pJ7N0oPEm5uNq_nSx0GqF0aEUMRiTqG1mY7f8mJtch7vJqxwWPlBZ32lrPmW0xswYLEx2sVZTnYFZqroZH31KePIpHoawrFTNuHQAsSCd1hI8Fj2gZ0ZfT8MFKftbx7_1Pum4KwK4eMv-W2urPsFH3-uU2G0wOaAi-yQ";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        assert_eq!(res, Ok("1234567890".to_owned()));
    }

    #[test]
    fn reject_bad_signature() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UiLCJleHAiOjIwMDAwMDAwMDB9.Pxj_GZChf9Cx70QAIpUpAPkJVFErhkxYrJCF3XHLyBdStWy17BrVVhnR2GBG5DCHOmI9jleUre-PUokETTu_nqAGhPB1fulouZUZwZPgJqS6kxQf4VSjumgTDUdmKyptAL2Yo1HOd-bqJrrSrLEST1iQgnWWuHmRcztQn89AxAGJkycAG6Pj8ot7qp3LC6xgOzlqL4mEqgLPNw-R_U_9Zr7Pqy8IbVWBxPz1rF9mPKPib1CLCQ_Jk_Ncmq_LyP70otyssmIEDvAovJn8tSsdIho9W4qGvSpHKeqZTxN0xJq-2KUXnORgrGOVu3cudc7SXmw31g3ZcRY09NUO0Q2uTg";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "bad signature was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_bad_kid() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFgzIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UiLCJleHAiOjIwMDAwMDAwMDB9.UzLMx80WPn8UG2RcWKxR9OSimouOI8Ag4bS5IHOzI0ueVG4qu55JvQGPEsKbevmEzVUchj1F-r2BgKK87TThQ4L112WgntNomV19kGUaGPPhkqrmMS5-bk3wAjhTCXgg84QeuMKlqN7PpF6MP1u98psWLfHHFXLl2Sy6aDsjtT8Hag8NmWn83sz2oNLqJfXmApZ3lFpwIT4o8B6ZTVF7USTNxHlt9vtA7OdYDF4V1ZPMRAf4xOStfUayOLoHwnv0YX3IR5NvVhuMo1Ej4p2S6_q8pjx-8-CM5gCFRNt0xSGG6LXdH971wTbvTDVfVeBEABmBul5KXVNOZ54YUkZcpQ";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::KidMismatch(_, _)) => assert!(true),
            _ => assert!(false, "incorrect kid was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_missing_sub() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJuYmYiOjE2NzU0NjE2ODgsImlzcyI6Imh0dHBzOi8vYXV0aC5wYXNzYWdlLmlkL3YxL2FwcHMvZmFrZSIsImV4cCI6MjAwMDAwMDAwMH0.orBGLQfdSKV1NLyJqXZapREZIT7BAb33vY1ovvM3lbHS9S7fNT_qZz-bQZZ_NkrL9nMB8mmX2A4PyHWfin1pHZOvhNKhcsVeIfZHBP9SYzUzXsWdqmSiPqd6VBAhQZs1OSwJz4K6JV4_igR40QImxRvg2AXcu3AiUdGU0nuuJ9Vtd7RwdXUx41cVpIyCiOsN4kPFpVaSYQ1-Qn9aowBea5j4h7EIhZaLAkTDJT3KuQxyxhJnO2-XubrQREwd8CilOIV1evrdaQkR4Xqw3FBcvjOiRW6zW0sIdANxk_jIqC2Vdp0feQKYvUFxea3xHAujz5TIi9q7sJzgJPBsjI1MzA";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "missing sub was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_missing_nbf() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnBhc3NhZ2UuaWQvdjEvYXBwcy9mYWtlIiwiZXhwIjoyMDAwMDAwMDAwfQ.lZ2zTZmJsIcQE2XDV-N8sVFvK2AxN4GWW_fId6yc2uSJFtQc26HcB0ywGn7BjhB8OD4rX3WkA9XqyUl51fKCnVlE8hlk4VlfDyewKahJkPmoqNX7QwDzA9ORd-5FlZJ1_8nsMzH0jn8ydkKJORgxGKfj_xZD73mW9gz31bVbYddPmPcAmhuJCvI_4dlNVmIfEk-UUNmtIJEc89iwbcg_baEUJDXXztUfYhw4M3WC58ptI5GZk9JLIcq5PU59Sn495d14Xeek19PD93ypSwsLRAwXXU6OQgRbFZtYdrshcDpZ3339RfuO6xBlTBqet5BbVMm-f28Mlqw2x2UvuQ_h-g";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "missing nbf was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_future_nbf() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoyMDAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UiLCJleHAiOjIwMDAwMDAwNjB9.HoPwswPk4euGoVyXZMlo2lwzUhHtXrzhyc5ZGy8QI0pStvkYB_fDyyPsL8u-TuHKdm5ezakQr1mvYdnJABpMi1X3qsUMYbU2Rs0Wk906YYnzMAmMANRkKAXw5uLTBjdWu_NG-KMYWom_N0rYGBGGAq5np8k1OHJWrZDJamCdqqcIY7n7hD4mwXMwzLoKRQQtojvtRijnzKGMThUfe7-0YrMPIi941P2Z86MSDXennU2cuoJXAMYndxfdNFXyt74DocTKXEfWR1gtdZqcUCG12TAhWxm_6qRjMcDTiO1gpXGjoommCMxgRU3Mm-XM734MHLMFWFma9Ldci8rbrmeypg";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "future nbf was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_missing_iss() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJleHAiOjIwMDAwMDAwMDB9.T61Xje9mZYOxQSIjvbV30gWqjz8kfZhqVG_KnCxmb3iXuERoTkjZFVZYeuHSKrTHMkxfrhAc7CjgREiHF1fJM9UCDWkl0CMpzfxfg5MVTF-ZoZ3cVmPjd4oslq5Ggjx7coo1kl7OhCY7w9XdGWGu7zCfMYmCNE-LwQ3h1Kj9NkxHv3HtcgKk6fvSdpMJ8IcIuGR-SLgr7yuQs9IBnwXb7tCSjY_5Lg3vpTpgB7_M2485Yyfx6ZUgUgY6u-8E3a2mMGbRtk3G6C_SnH4HTvkn2QGNd9b5F6Llcs4aQpKuSe--GIJg4FNVTKJ0M_27ycSZYu-UMolVmUm4QUqZCmLZzQ";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "missing iss was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_wrong_iss() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL3dyb25nIiwiZXhwIjoyMDAwMDAwMDAwfQ.DTLsHvjK7ewJ1aajQdddMtHH2rx5ripQzjubOzZExNmtGvaVHUAlaa9vO_gu4NgpGg8m11IotqfeZUqLxVSSJ_GBLFVXcvBp2hRILs8JyU2uRdgur_n6Re1GoQpsfPqNxAdjDnRLE9QaXDDk-ErG3xdM4tDW9x_UGnrnlPAhePhGEXDSYzSDe0RmXFKcS0AzkQMztwiEW3HWunxVmZhMniPVWfzAuFqO28VVzLIpMFDsBsseHUzFhBDyzshNGHmk1t4pgEUXafrqi_DR_ammxP5Wp8U-4syzgNZ1WvVs7hJeXgDHAV3xwMH083p8p1HqqLsz5Zfqw8A6yu8TkcEctw";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "wrong iss was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_missing_exp() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UifQ.BXvWfR2zFI-Tm72BAZgqQuykfzs4cOswlPP_H-8usiBAwpg6LExhWis9R8YJch5fcHAUfgbIMxZnwhylfESXrqs9QxAarn0M3NIGF8bI32nTNPrQpBUJCzdYh6OCaJ8G7lftY2LTDcGHq0v18ikILykoloN69wjys-eStrW2yr3_XIGSkHpbOjVSSru30XTRndT30rImytR8EBsWN0vsgyucy2X0-NCfsfa3Wl4vQUV5nxtO1ejpTmr0LvfHENEXyEoA2Q5Rr5PuLHF03kbLjlD81OPPETUZdPPKclyjlPozKraX6TnvUGVQq4XM00YlL5qoUZ4HBLIVusKi_d9kPw";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "missing exp was not properly rejected: {:?}", res),
        }
    }

    #[test]
    fn reject_past_exp() {
        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNjc1NDYxNjg4LCJpc3MiOiJodHRwczovL2F1dGgucGFzc2FnZS5pZC92MS9hcHBzL2Zha2UiLCJleHAiOjE2NzU0NjE4ODh9.YJlpsocdeIAaMATZDBz5EsdbOhtNDTDGr4_j7mEtWthU0JJdhWIoNxaX5Dep1C9yNf8hFFg0r3re6ImoQz4-vMkOGmObUxAP-7hlMEhfx8ww7Slj1vn_3ZEAHrp3JUS4jirQNak9-qvOr4Ndh0XsvzVAWca216hAo2PMXZwmaS8vBG8bpm5sVFevB6f-rW3OVEgafcmagRlFpgXLum6vcw18nsRV9qcvcQZDlW9x7Z7cJEW13e35qWz_urdOgB9EdD_feVuG1zlE_MbBgE6EtSNTumlqnB_Iae1KeM-nHJkeKkCbfvbd1WCc5lI3N8mv0M7m7nRBxQM6TFSbXqrI2g";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, PUB_JWK);

        match res {
            Err(AuthError::TokenDecoding(_)) => assert!(true),
            _ => assert!(false, "past exp was not properly rejected: {:?}", res),
        }
    }
}

/* Private key for test:
{
    "p": "9WRlEysjzbea25MPFvMMioGvShW4vZD0Qhhc4yVRZz0PpRXpW5wVQKMJqd1N7vfiXA_OMtGY3pTMegUhF_Mw7W2S1b0_2V_xAXYt8g4G0IY0aT9GBETB63ga4FLccJCSkjIagtt5TOhO5IOIDboghEKkQvguNTSJPi3J5Dvp_PM",
    "kty": "RSA",
    "q": "tAdPC8Yo08Cb951vkfWmjZyJuosjRHcWugvrVivnuWVyHouuX9ktbE-JRREhQ7o-58EXJZJ_el07_IE1xKoKlaJ3saEOfWDOApDiJxbbwwnMGCTqdsi8Q07DN4PgYFcSr5MXd9ZFemqVBXW84yFKVXPNKXfR_VoI9GlURQU6YDM",
    "d": "J_qnHeQNnt0jDBbjiH-LmE6vvE6ZHwtPUiFlJg2XD3FaymEro3MDakQ9wsIrgeyyGQk-D7RMm4BsZ6Dk3cqe6hN38sziSYSssktKPvBpqF9COEu8rSuNys8bx_rovv2ksdD0BrzZ-tWKaNIfnYsiqIuexwduDALn1_p10CvCa9HvY9Z_wcuW4hazdMDXZhQIDexldd6hpdB4XgIftqmvrMV7uTCENcLrZ_daJO_dKugybin828asAjXzua2sNCD3QYKmWVR65p-4PBDBKPFWyEuV3C2zpPE_rBex-B1iOwKwlF_-UPMSpPbaGzgyB2Nl4k1UQ7CZBMWswFnS6FnJ_Q",
    "e": "AQAB",
    "use": "sig",
    "kid": "r50vKukJl4oVaT78O0ELIGS4w8ynMY_4lRSBq-uvTX4",
    "qi": "7-uVCCf2T6nQcp4_jHt1YA6hb9anJY5NjA-kPtm4OcbUKQD5i3XoM7Gu3vMgw0fYdLigDa4Nt6qmpOK-On0S74fJdL4iR_8dsq6ytO1Q3Sl7xkvZmNRiQV2lr-DNLR5Wl8UCeoDmKzF8u3Y1riUkr9sk-mrLTWqMSK_r2Th5NKc",
    "dp": "62Ix0gE_hsTntleJ0emxzeo3ykirvKqeogfckcXqH61ipGgwP7-oYygAzP-LEf6VEtnWYMjMajUxLppc9CxCcnz4rC2sYUa2V0CVMepifwM8ovgeoVmS6dt7bFIPQapr7fBBneQIpszvYCMLDp_LMRL7nYGSUVbjjtE9J8CQ4iE",
    "alg": "RS256",
    "dq": "PnMimoT8-Keh8v1sDIfYZNtec5V8gG2HNraXxmaolYl5UttFe_5MYXwdtBXDIkljNOWob-In0nyxKGByFGygC1Q2jSm_awK_s-gqa0Dkrv2hDOcRZm8vz3FtCr72gLTzyHAP_gQYSeTbGO_EvE16CbaH_tCPyYEIBjDbiK3NmD0",
    "n": "rJGYlYJPZZmeZUyxtEdbbzyMZrBbJPMbhkaioazk6_43d9SIYcVWouei6R5WXQrO6chx3HaSUOqRcYv4oF9x6FVrBWSGyxbzjltcnwKOWn3K8qmJWQvv2nLvLJvf_wdUR2IlH2SfGEE9Om6mJG6tw4Hvn0FauCvnS_a5E5oi0-Mp8rDK3KaHKTr7YHPNzKZzYryF8Ids2mb7PULxFNErIUmB6yTuxUjmbLXwRK2nHe2gHnaepYqcTZIQcTgfS8NeAqKUHWwRkvqmi_pIr9g8azwCqQ8cHpaOoxyUtTlSva1ggkiinJdeIP1-RF-ElflqGtqLXF9OJc8Kcd1ivIaEaQ"
}
*/
