// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Product tokens (`hub.v1`, docs/hub-protocol.md): a product proves who it is
//! with a JWT signed by its own Ed25519 key (RFC 7523 `private_key_jwt`) and
//! gets a short EdDSA access token for one audience and its granted scopes.
//! No secret is shared: AIS holds only the products' public keys.

use std::collections::{BTreeSet, HashMap};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// The audience a product names to get a token for AIS itself, such as the
/// one Prism Hub presents to ask for a person pass. Never a client id.
pub const AIS_AUDIENCE: &str = "ais";
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The longest an assertion may live, and how long a product token lives.
pub const TOKEN_TTL: u64 = 5 * 60;
/// Clock difference tolerated between a product and AIS.
const LEEWAY: u64 = 30;
const MAX_ASSERTION_BYTES: usize = 4096;

/// What a product may do, from its registry entry.
#[derive(Clone, Debug)]
pub struct Product {
    /// Its public keys by `kid`.
    pub keys: HashMap<String, VerifyingKey>,
    /// The audiences it may ask a token for, each with the scopes it may hold.
    pub tokens: HashMap<String, BTreeSet<String>>,
    /// A relay (Prism Hub) may name the product it acts for (`act`).
    pub relay: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AssertionError {
    Malformed,
    UnknownKey,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    Expired,
    TooLong,
    NotYetValid,
}

/// A verified assertion: who signed it and what makes it single-use.
#[derive(Debug, Eq, PartialEq)]
pub struct Assertion {
    pub client_id: String,
    pub jti: String,
    pub expires_at: u64,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(one) => one == value,
            Self::Many(many) => many.iter().any(|one| one == value),
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    jti: String,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

fn decode<T: for<'a> Deserialize<'a>>(part: &str) -> Option<T> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

/// The client an assertion claims to come from, read before anything is
/// verified, only to find its keys.
pub fn claimed_client(assertion: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    decode::<Claims>(payload).map(|claims| claims.iss)
}

/// Verifies `assertion` against `product`'s keys. `audiences` are the values
/// AIS accepts as `aud`: its issuer and its token endpoint.
pub fn verify_assertion(
    assertion: &str,
    client_id: &str,
    product: &Product,
    audiences: &[&str],
    now: u64,
) -> Result<Assertion, AssertionError> {
    if assertion.len() > MAX_ASSERTION_BYTES {
        return Err(AssertionError::Malformed);
    }
    let mut parts = assertion.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AssertionError::Malformed);
    };
    let header: Header = decode(header).ok_or(AssertionError::Malformed)?;
    if header.alg != "EdDSA" {
        return Err(AssertionError::Malformed);
    }
    let key = product
        .keys
        .get(&header.kid)
        .ok_or(AssertionError::UnknownKey)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(AssertionError::Malformed)?;
    // Three parts were found, so the last dot is the one before the signature.
    let signed = &assertion[..assertion.rfind('.').ok_or(AssertionError::Malformed)?];
    key.verify_strict(signed.as_bytes(), &signature)
        .map_err(|_| AssertionError::BadSignature)?;
    let claims: Claims = decode(payload).ok_or(AssertionError::Malformed)?;
    if claims.iss != client_id || claims.sub != client_id {
        return Err(AssertionError::WrongIssuer);
    }
    if !audiences
        .iter()
        .any(|audience| claims.aud.contains(audience))
    {
        return Err(AssertionError::WrongAudience);
    }
    if claims.exp <= now {
        return Err(AssertionError::Expired);
    }
    if claims.exp > now + TOKEN_TTL + LEEWAY {
        return Err(AssertionError::TooLong);
    }
    if claims.iat.is_some_and(|iat| iat > now + LEEWAY)
        || claims.nbf.is_some_and(|nbf| nbf > now + LEEWAY)
    {
        return Err(AssertionError::NotYetValid);
    }
    if !(16..=128).contains(&claims.jti.len())
        || !claims
            .jti
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AssertionError::Malformed);
    }
    Ok(Assertion {
        client_id: claims.iss,
        jti: claims.jti,
        expires_at: claims.exp,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub enum GrantError {
    /// The audience is not one this product may ask for.
    Target,
    /// A scope it asked for is not granted for that audience.
    Scope,
}

/// The scopes to grant: those asked for, or all granted when none are asked.
pub fn grant_scopes(
    product: &Product,
    audience: &str,
    requested: Option<&str>,
) -> Result<BTreeSet<String>, GrantError> {
    let allowed = product.tokens.get(audience).ok_or(GrantError::Target)?;
    let Some(requested) = requested.filter(|value| !value.trim().is_empty()) else {
        return Ok(allowed.clone());
    };
    let mut scopes = BTreeSet::new();
    for scope in requested.split(' ').filter(|scope| !scope.is_empty()) {
        if !allowed.contains(scope) {
            return Err(GrantError::Scope);
        }
        scopes.insert(scope.to_owned());
    }
    Ok(scopes)
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    pub(crate) fn assertion(key: &SigningKey, kid: &str, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = key.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn product(key: &SigningKey) -> Product {
        Product {
            keys: HashMap::from([("k1".to_owned(), key.verifying_key())]),
            tokens: HashMap::from([(
                "prism-hub".to_owned(),
                BTreeSet::from(["hub.call".to_owned(), "hub.events".to_owned()]),
            )]),
            relay: false,
        }
    }

    const NOW: u64 = 1_000_000;
    const AUD: &str = "https://auth.aiaiaiai.org/token";

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "0xda-market", "sub": "0xda-market", "aud": AUD,
            "exp": NOW + 60, "iat": NOW, "jti": "a-unique-assertion-id",
        })
    }

    #[test]
    fn a_signed_assertion_names_its_product() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let jwt = assertion(&key, "k1", &claims());
        assert_eq!(claimed_client(&jwt).as_deref(), Some("0xda-market"));
        assert_eq!(
            verify_assertion(&jwt, "0xda-market", &product(&key), &[AUD], NOW),
            Ok(Assertion {
                client_id: "0xda-market".into(),
                jti: "a-unique-assertion-id".into(),
                expires_at: NOW + 60,
            })
        );
    }

    #[test]
    fn a_forged_stale_or_misdirected_assertion_is_refused() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let other = SigningKey::from_bytes(&[6; 32]);
        let check = |jwt: &str| verify_assertion(jwt, "0xda-market", &product(&key), &[AUD], NOW);
        let with = |field: &str, value: serde_json::Value| {
            let mut claims = claims();
            claims[field] = value;
            assertion(&key, "k1", &claims)
        };
        assert_eq!(
            check(&assertion(&other, "k1", &claims())),
            Err(AssertionError::BadSignature)
        );
        assert_eq!(
            check(&assertion(&key, "k2", &claims())),
            Err(AssertionError::UnknownKey)
        );
        assert_eq!(
            check(&with("iss", "0x1".into())),
            Err(AssertionError::WrongIssuer)
        );
        assert_eq!(
            check(&with("sub", "0x1".into())),
            Err(AssertionError::WrongIssuer)
        );
        assert_eq!(
            check(&with("aud", "https://elsewhere.example/token".into())),
            Err(AssertionError::WrongAudience)
        );
        assert_eq!(
            check(&with("exp", NOW.into())),
            Err(AssertionError::Expired)
        );
        assert_eq!(
            check(&with("exp", (NOW + 3600).into())),
            Err(AssertionError::TooLong)
        );
        assert_eq!(
            check(&with("iat", (NOW + 3600).into())),
            Err(AssertionError::NotYetValid)
        );
        assert_eq!(
            check(&with("jti", "short".into())),
            Err(AssertionError::Malformed)
        );
        // A token for the right key but with its payload swapped fails the
        // signature, not the claims.
        let jwt = assertion(&key, "k1", &claims());
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let forged_payload = with("jti", "another-assertion-id".into());
        parts[1] = forged_payload.split('.').nth(1).unwrap();
        assert_eq!(check(&parts.join(".")), Err(AssertionError::BadSignature));
        assert_eq!(check("not.a.jwt"), Err(AssertionError::Malformed));
        assert_eq!(check(&"a".repeat(5000)), Err(AssertionError::Malformed));
    }

    #[test]
    fn an_array_audience_is_accepted_when_it_names_ais() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let mut claims = claims();
        claims["aud"] = serde_json::json!(["https://other.example", AUD]);
        let jwt = assertion(&key, "k1", &claims);
        assert!(verify_assertion(&jwt, "0xda-market", &product(&key), &[AUD], NOW).is_ok());
    }

    #[test]
    fn scopes_are_those_granted_for_the_audience() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let product = product(&key);
        assert_eq!(
            grant_scopes(&product, "prism-hub", None).unwrap(),
            BTreeSet::from(["hub.call".to_owned(), "hub.events".to_owned()])
        );
        assert_eq!(
            grant_scopes(&product, "prism-hub", Some("hub.call")).unwrap(),
            BTreeSet::from(["hub.call".to_owned()])
        );
        assert_eq!(
            grant_scopes(&product, "prism-hub", Some("hub.call wallet.debit")),
            Err(GrantError::Scope)
        );
        assert_eq!(grant_scopes(&product, "0x1", None), Err(GrantError::Target));
    }
}
