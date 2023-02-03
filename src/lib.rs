use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;

pub struct Passage {
    app_id: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
}

#[derive(Debug, PartialEq)]
pub enum AuthError {
    TokenHeaderDecoding(jwt::errors::Error),
    KidMismatch(Option<String>, Option<String>),
    PubKeyParsing(String),
    BadIssuer(String),
    TokenDecoding(jwt::errors::Error),
}

impl Passage {
    pub fn new(app_id: String) -> Self {
        Passage { app_id }
    }

    pub fn authenticate_token(self, token: &str, pub_jwk: &str) -> Result<String, AuthError> {
        let key = pub_jwk
            .parse::<jwk::JsonWebKey>()
            .map_err(|e| AuthError::PubKeyParsing(e.to_string()))?;

        let header = jwt::decode_header(token).map_err(AuthError::TokenHeaderDecoding)?;

        if header.kid != key.key_id {
            return Err(AuthError::KidMismatch(header.kid, key.key_id));
        }

        let token = jwt::decode::<Claims>(
            &token,
            &key.key.to_decoding_key(),
            &jwt::Validation::new(jwt::Algorithm::RS256),
        )
        .map_err(AuthError::TokenDecoding)?;

        if token.claims.iss != (String::from("https://auth.passage.id/v1/apps/") + &self.app_id) {
            return Err(AuthError::BadIssuer(token.claims.iss));
        }

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

    #[test]
    fn authenticate_token() {
        // Generated using https://mkjwk.org/
        let jwk_str = r#"{
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "r50vKukJl4oVaT78O0ELIGS4w8ynMY_4lRSBq-uvTX4",
            "alg": "RS256",
            "n": "rJGYlYJPZZmeZUyxtEdbbzyMZrBbJPMbhkaioazk6_43d9SIYcVWouei6R5WXQrO6chx3HaSUOqRcYv4oF9x6FVrBWSGyxbzjltcnwKOWn3K8qmJWQvv2nLvLJvf_wdUR2IlH2SfGEE9Om6mJG6tw4Hvn0FauCvnS_a5E5oi0-Mp8rDK3KaHKTr7YHPNzKZzYryF8Ids2mb7PULxFNErIUmB6yTuxUjmbLXwRK2nHe2gHnaepYqcTZIQcTgfS8NeAqKUHWwRkvqmi_pIr9g8azwCqQ8cHpaOoxyUtTlSva1ggkiinJdeIP1-RF-ElflqGtqLXF9OJc8Kcd1ivIaEaQ"
        }"#;

        let jwt_str = "eyJraWQiOiJyNTB2S3VrSmw0b1ZhVDc4TzBFTElHUzR3OHluTVlfNGxSU0JxLXV2VFg0IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnBhc3NhZ2UuaWQvdjEvYXBwcy9mYWtlIiwiZXhwIjoyMDAwMDAwMDAwfQ.lZ2zTZmJsIcQE2XDV-N8sVFvK2AxN4GWW_fId6yc2uSJFtQc26HcB0ywGn7BjhB8OD4rX3WkA9XqyUl51fKCnVlE8hlk4VlfDyewKahJkPmoqNX7QwDzA9ORd-5FlZJ1_8nsMzH0jn8ydkKJORgxGKfj_xZD73mW9gz31bVbYddPmPcAmhuJCvI_4dlNVmIfEk-UUNmtIJEc89iwbcg_baEUJDXXztUfYhw4M3WC58ptI5GZk9JLIcq5PU59Sn495d14Xeek19PD93ypSwsLRAwXXU6OQgRbFZtYdrshcDpZ3339RfuO6xBlTBqet5BbVMm-f28Mlqw2x2UvuQ_h-g";

        let passage = Passage::new(String::from("fake"));
        let res = passage.authenticate_token(jwt_str, jwk_str);

        assert_eq!(res, Ok("1234567890".to_owned()));
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
