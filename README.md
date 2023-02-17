<img src="https://storage.googleapis.com/passage-docs/passage-logo-gradient.svg" alt="Passage logo" style="width:250px;"/>

# Passage SDK for Rust

This crate provides a library for working with [Passage](https://passage.id), a modern passwordless authentication experience based on Passkeys and magic links. This library currently implements a very small subset of the available Passage API endpoints.

At the moment, this SDK assists with server-side authentication.

## Installation

```
cargo add passage-id
```

## Example: validation of Passage JWTs

```rust
extern crate passage_id;
use crate::passage_id::Passage;

fn main() {
    // Your app id from https://console.passage.id/settings
    let app_id = "...";

    // Your app's public jwk key from https://auth.passage.id/v1/apps/{app_id}/.well-known/jwks.json.
    let pub_key = r#"{
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": "...",
        "e": "AQAB",
        "kid": "..."
      }"#;

    // If you are using an Element, the Passage JWT will be sent to your application via a cookie with the key `psg_auth_token`
    let psg_auth_token = "...";
    let passage = Passage::new(String::from(app_id));
    let result = passage.authenticate_token(psg_auth_token, pub_key);

    match result {
        Ok(passage_user_id) => println!(
            "Passage JWT is valid. passage_user_id=<{}>",
            passage_user_id
        ),
        Err(err) => {
            println!("Auth error: {:?}", err);
        }
    }
}
```
