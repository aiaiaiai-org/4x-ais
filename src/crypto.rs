// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Keys derived from `AIS_SECRET`, signed values, pairwise subjects and JWS.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of every length");
    for part in parts {
        // Length-prefixed, so no two part lists hash alike.
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// One independent key per purpose, all from the single `AIS_SECRET`.
#[derive(Clone)]
pub struct Keys {
    pairwise: [u8; 32],
    sealing: [u8; 32],
}

impl Keys {
    pub fn derive(secret: &[u8]) -> Self {
        Self {
            pairwise: hmac(secret, &[b"ais-key", b"pairwise-v1"]),
            sealing: hmac(secret, &[b"ais-key", b"sealing-v1"]),
        }
    }

    /// The `sub` a client sees: a keyed digest of the client id and the
    /// private subject. Stable for one client, unlinkable across clients,
    /// never the subject itself.
    pub fn pairwise_subject(&self, client_id: &str, subject: &[u8; 32]) -> String {
        URL_SAFE_NO_PAD.encode(hmac(
            &self.pairwise,
            &[b"sub", client_id.as_bytes(), subject],
        ))
    }

    /// A tamper-evident value for a cookie or form field. Not encrypted: it
    /// must hold nothing the browser may not see.
    pub fn seal<T: Serialize>(&self, domain: &str, value: &T) -> String {
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("sealed values serialize"));
        let mac = hmac(&self.sealing, &[domain.as_bytes(), payload.as_bytes()]);
        format!("v1.{payload}.{}", URL_SAFE_NO_PAD.encode(mac))
    }

    pub fn open<T: DeserializeOwned>(&self, domain: &str, sealed: &str) -> Option<T> {
        let mut fields = sealed.split('.');
        let (Some("v1"), Some(payload), Some(mac), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        let supplied = URL_SAFE_NO_PAD.decode(mac).ok()?;
        let expected = hmac(&self.sealing, &[domain.as_bytes(), payload.as_bytes()]);
        if !bool::from(supplied.ct_eq(&expected)) {
            return None;
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
    }
}

pub fn random_bytes<const N: usize>() -> Option<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

pub fn random_token(bytes: usize) -> Option<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).ok()?;
    Some(URL_SAFE_NO_PAD.encode(value))
}

/// A compact EdDSA JWS.
pub fn sign_jwt(key: &SigningKey, key_id: &str, claims: &serde_json::Value) -> String {
    sign_jwt_typed(key, key_id, "JWT", claims)
}

/// A compact EdDSA JWS with an explicit `typ`, such as `at+jwt` (RFC 9068),
/// so a product token can never be mistaken for an `id_token`.
pub fn sign_jwt_typed(
    key: &SigningKey,
    key_id: &str,
    typ: &str,
    claims: &serde_json::Value,
) -> String {
    let header = serde_json::json!({ "alg": "EdDSA", "typ": typ, "kid": key_id });
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_open_only_with_the_same_key_and_domain() {
        let keys = Keys::derive(b"a-secret-that-is-at-least-32-bytes-long");
        let sealed = keys.seal("request", &("x", 1));
        assert_eq!(
            keys.open::<(String, u32)>("request", &sealed),
            Some(("x".into(), 1))
        );
        assert_eq!(keys.open::<(String, u32)>("hint", &sealed), None);
        let other = Keys::derive(b"another-secret-that-is-at-least-32-bytes");
        assert_eq!(other.open::<(String, u32)>("request", &sealed), None);
        let tampered = sealed.replacen("v1.", "v1.A", 1);
        assert_eq!(keys.open::<(String, u32)>("request", &tampered), None);
    }

    #[test]
    fn pairwise_subjects_are_per_client_and_hide_the_subject() {
        let keys = Keys::derive(b"a-secret-that-is-at-least-32-bytes-long");
        let subject = [7_u8; 32];
        let a = keys.pairwise_subject("nilx-one", &subject);
        assert_eq!(a, keys.pairwise_subject("nilx-one", &subject));
        assert_ne!(a, keys.pairwise_subject("prism", &subject));
        assert_ne!(a, keys.pairwise_subject("nilx-one", &[8_u8; 32]));
        assert!(!a.contains(&URL_SAFE_NO_PAD.encode(subject)));
    }
}
