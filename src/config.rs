// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Runtime configuration. Every setting arrives in the environment, and the
//! host generates the secrets once (`deploy/prepare-runtime-env.sh`); infra only
//! runs that script (docs/runtime.md).

use std::collections::{BTreeSet, HashMap};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::product_token::Product;

const MIN_SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("AIS_ISSUER must be an https origin")]
    Issuer,
    #[error("AIS_SIGNING_KEY must be a base64url 32-byte Ed25519 seed")]
    SigningKey,
    #[error("{0} must be at least 32 bytes")]
    ShortSecret(&'static str),
    #[error("AIS_CLIENTS is invalid: {0}")]
    Clients(String),
    #[error("AIS_BIND must be a socket address")]
    Bind,
}

/// How a client's page presents the address. Security is identical for both.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Skin {
    /// 0x-friendly products (0x1, 0xda-market): the person sees and chooses
    /// the whole prefix, one of `0x0`–`0xf`.
    Cell,
    /// Every other product: only the slug is shown; AIS assigns the prefix.
    Slug,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRecord {
    client_id: String,
    name: String,
    skin: Skin,
    redirect_uris: Vec<String>,
    /// Lowercase hex SHA-256 of the client secret. The secret itself never
    /// reaches AIS configuration. Absent for a public client: one that holds
    /// no secret and proves a code only with its PKCE verifier.
    #[serde(default)]
    secret_sha256: Option<String>,
    #[serde(default)]
    pub_dress: bool,
    /// Present for a family product that may ask for product tokens.
    #[serde(default)]
    product: Option<ProductRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductRecord {
    keys: Vec<ProductKeyRecord>,
    /// Audience (another client id) → the scopes the product may hold for it.
    #[serde(default)]
    tokens: HashMap<String, Vec<String>>,
    #[serde(default)]
    relay: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductKeyRecord {
    kid: String,
    /// The Ed25519 public key, base64url, 32 bytes.
    x: String,
}

const MAX_PRODUCT_KEYS: usize = 4;

/// A server-registered client. `name` and `skin` change presentation only.
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub skin: Skin,
    pub redirect_uris: Vec<String>,
    /// `None` for a public client. PKCE (S256, always required) and the exact
    /// redirect URI are what bind a code to it.
    pub secret_sha256: Option<[u8; 32]>,
    pub pub_dress_scope: bool,
    /// `Some` for a family product: its keys and token grants.
    pub product: Option<Product>,
}

#[derive(Clone)]
pub struct Config {
    pub issuer: Url,
    pub signing_key: SigningKey,
    pub key_id: String,
    pub secret: Vec<u8>,
    pub password_pepper: Vec<u8>,
    pub clients: HashMap<String, Client>,
    pub database_url: String,
    pub bind: std::net::SocketAddr,
}

impl Config {
    /// Reads the configuration through `get`, so tests need no process
    /// environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let read = |key: &'static str| {
            get(key)
                .filter(|value| !value.is_empty())
                .ok_or(ConfigError::Missing(key))
        };
        let issuer = parse_issuer(&read("AIS_ISSUER")?)?;
        let signing_key = parse_signing_key(&read("AIS_SIGNING_KEY")?)?;
        let secret = read("AIS_SECRET")?.into_bytes();
        if secret.len() < MIN_SECRET_BYTES {
            return Err(ConfigError::ShortSecret("AIS_SECRET"));
        }
        let password_pepper = read("AIS_PASSWORD_PEPPER")?.into_bytes();
        if password_pepper.len() < MIN_SECRET_BYTES {
            return Err(ConfigError::ShortSecret("AIS_PASSWORD_PEPPER"));
        }
        let clients = parse_clients(&read("AIS_CLIENTS")?)?;
        let database_url = get("AIS_DATABASE_URL")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "sqlite:///data/ais.db".to_owned());
        let bind = get("AIS_BIND")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "0.0.0.0:1927".to_owned())
            .parse()
            .map_err(|_| ConfigError::Bind)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signing_key.verifying_key().as_bytes()))
            [..16]
            .to_owned();
        Ok(Self {
            issuer,
            signing_key,
            key_id,
            secret,
            password_pepper,
            clients,
            database_url,
            bind,
        })
    }

    /// The `iss` value: the origin without its trailing slash.
    pub fn issuer_id(&self) -> &str {
        self.issuer.as_str().trim_end_matches('/')
    }

    /// `host[:port]` as browsers send it in `Host`.
    pub fn issuer_host(&self) -> String {
        let host = self.issuer.host_str().unwrap_or_default();
        match self.issuer.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }
}

fn parse_issuer(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Issuer)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Issuer);
    }
    Ok(url)
}

fn parse_signing_key(value: &str) -> Result<SigningKey, ConfigError> {
    let seed = URL_SAFE_NO_PAD
        .decode(value.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(ConfigError::SigningKey)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_clients(value: &str) -> Result<HashMap<String, Client>, ConfigError> {
    let records: Vec<ClientRecord> =
        serde_json::from_str(value).map_err(|error| ConfigError::Clients(error.to_string()))?;
    let mut clients = HashMap::new();
    for record in records {
        let client = Client::try_from(record).map_err(ConfigError::Clients)?;
        if clients.insert(client.client_id.clone(), client).is_some() {
            return Err(ConfigError::Clients("duplicate client_id".into()));
        }
    }
    // A product may ask for tokens only to other registered products.
    for client in clients.values() {
        let Some(product) = &client.product else {
            continue;
        };
        for audience in product.tokens.keys() {
            if audience == &client.client_id
                || clients
                    .get(audience)
                    .is_none_or(|target| target.product.is_none())
            {
                return Err(ConfigError::Clients(format!(
                    "{}: token audience {audience:?} is not another registered product",
                    client.client_id
                )));
            }
        }
    }
    if clients.is_empty() {
        return Err(ConfigError::Clients(
            "at least one client is required".into(),
        ));
    }
    Ok(clients)
}

impl TryFrom<ClientRecord> for Client {
    type Error = String;

    fn try_from(record: ClientRecord) -> Result<Self, String> {
        let id = &record.client_id;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(format!("invalid client_id {id:?}"));
        }
        if record.name.trim().is_empty() || record.name.len() > 64 {
            return Err(format!("{id}: name must be 1-64 bytes"));
        }
        // A product that only speaks to other products signs nobody in.
        if record.redirect_uris.is_empty() && record.product.is_none() {
            return Err(format!("{id}: at least one redirect URI is required"));
        }
        for uri in &record.redirect_uris {
            let parsed = Url::parse(uri).map_err(|_| format!("{id}: invalid redirect URI"))?;
            if parsed.scheme() != "https" || parsed.fragment().is_some() || parsed.as_str() != uri {
                return Err(format!("{id}: redirect URIs must be normalized https URLs"));
            }
        }
        let secret_sha256 = record
            .secret_sha256
            .as_deref()
            .map(|value| {
                decode_hex32(value)
                    .ok_or_else(|| format!("{id}: secret_sha256 must be 64 lowercase hex digits"))
            })
            .transpose()?;
        let product = record
            .product
            .map(|product| parse_product(id, product))
            .transpose()?;
        Ok(Self {
            client_id: record.client_id,
            name: record.name,
            skin: record.skin,
            redirect_uris: record.redirect_uris,
            secret_sha256,
            pub_dress_scope: record.pub_dress,
            product,
        })
    }
}

fn is_token_word(value: &str, extra: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || extra.contains(&byte))
}

fn parse_product(id: &str, record: ProductRecord) -> Result<Product, String> {
    if record.keys.is_empty() || record.keys.len() > MAX_PRODUCT_KEYS {
        return Err(format!("{id}: a product holds 1-{MAX_PRODUCT_KEYS} keys"));
    }
    let mut keys = HashMap::new();
    for key in record.keys {
        if key.kid.is_empty()
            || key.kid.len() > 64
            || !key
                .kid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(format!("{id}: invalid key id {:?}", key.kid));
        }
        let public = URL_SAFE_NO_PAD
            .decode(key.x.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .filter(|public| !public.is_weak())
            .ok_or_else(|| format!("{id}: key {:?} is not an Ed25519 public key", key.kid))?;
        if keys.insert(key.kid.clone(), public).is_some() {
            return Err(format!("{id}: duplicate key id {:?}", key.kid));
        }
    }
    let mut tokens = HashMap::new();
    for (audience, scopes) in record.tokens {
        if scopes.is_empty() {
            return Err(format!("{id}: no scopes for audience {audience:?}"));
        }
        let mut set = BTreeSet::new();
        for scope in scopes {
            if !is_token_word(&scope, b"._:-") || !set.insert(scope.clone()) {
                return Err(format!("{id}: invalid or repeated scope {scope:?}"));
            }
        }
        tokens.insert(audience, set);
    }
    Ok(Product {
        keys,
        tokens,
        relay: record.relay,
    })
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn lookup(overrides: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut values: HashMap<String, String> = [
            ("AIS_ISSUER", "https://auth.aiaiaiai.org"),
            ("AIS_SIGNING_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"),
            ("AIS_SECRET", "a-test-secret-that-is-at-least-32-bytes"),
            ("AIS_PASSWORD_PEPPER", "a-test-pepper-that-is-at-least-32-bytes"),
            (
                "AIS_CLIENTS",
                r#"[{"client_id":"nilx-one","name":"0x1","skin":"cell","redirect_uris":["https://nilx.one/cb"],"secret_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]"#,
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        for (key, value) in overrides {
            values.insert((*key).to_owned(), (*value).to_owned());
        }
        move |key| values.get(key).cloned()
    }

    #[test]
    fn reads_a_complete_configuration() {
        let config = Config::from_lookup(lookup(&[])).unwrap();
        assert_eq!(config.issuer_id(), "https://auth.aiaiaiai.org");
        assert_eq!(config.issuer_host(), "auth.aiaiaiai.org");
        assert_eq!(config.clients["nilx-one"].skin, Skin::Cell);
        assert_eq!(config.bind.port(), 1927);
    }

    #[test]
    fn a_client_may_hold_no_secret_but_not_a_malformed_one() {
        let public = r#"[{"client_id":"open-app","name":"Open","skin":"slug","redirect_uris":["https://open.example/cb"]}]"#;
        let config = Config::from_lookup(lookup(&[("AIS_CLIENTS", public)])).unwrap();
        assert_eq!(config.clients["open-app"].secret_sha256, None);
        let malformed = r#"[{"client_id":"open-app","name":"Open","skin":"slug","redirect_uris":["https://open.example/cb"],"secret_sha256":"not-hex"}]"#;
        assert!(matches!(
            Config::from_lookup(lookup(&[("AIS_CLIENTS", malformed)])).err(),
            Some(ConfigError::Clients(_))
        ));
    }

    fn product_key(seed: u8) -> String {
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    }

    #[test]
    fn a_product_holds_keys_and_grants_for_other_products() {
        let clients = serde_json::json!([
            { "client_id": "0xda-market", "name": "0xda-market", "skin": "cell",
              "redirect_uris": ["https://0xda-market.nilx.one/cb"],
              "product": { "keys": [{ "kid": "m1", "x": product_key(1) }],
                           "tokens": { "prism-hub": ["hub.call"] } } },
            { "client_id": "prism-hub", "name": "Prism Hub", "skin": "slug", "redirect_uris": [],
              "product": { "keys": [{ "kid": "h1", "x": product_key(2) }],
                           "tokens": { "0xda-market": ["hub.relay"] }, "relay": true } },
        ])
        .to_string();
        let config = Config::from_lookup(lookup(&[("AIS_CLIENTS", &clients)])).unwrap();
        let market = config.clients["0xda-market"].product.as_ref().unwrap();
        assert!(market.keys.contains_key("m1"));
        assert!(market.tokens["prism-hub"].contains("hub.call"));
        assert!(!market.relay);
        assert!(config.clients["prism-hub"].product.as_ref().unwrap().relay);
        assert!(config.clients["prism-hub"].redirect_uris.is_empty());
    }

    #[test]
    fn a_product_registry_entry_is_checked_whole() {
        let err = |clients: serde_json::Value| {
            Config::from_lookup(lookup(&[("AIS_CLIENTS", &clients.to_string())])).err()
        };
        let entry = |product: serde_json::Value| {
            serde_json::json!([
                { "client_id": "a", "name": "A", "skin": "slug", "redirect_uris": [], "product": product },
                { "client_id": "b", "name": "B", "skin": "slug", "redirect_uris": [],
                  "product": { "keys": [{ "kid": "b1", "x": product_key(3) }] } },
                { "client_id": "c", "name": "C", "skin": "slug", "redirect_uris": ["https://c.example/cb"] },
            ])
        };
        let key = serde_json::json!([{ "kid": "a1", "x": product_key(4) }]);
        assert!(
            err(entry(
                serde_json::json!({ "keys": key, "tokens": { "b": ["x"] } })
            ))
            .is_none()
        );
        for product in [
            serde_json::json!({ "keys": [] }),
            serde_json::json!({ "keys": [{ "kid": "a1", "x": "short" }] }),
            serde_json::json!({ "keys": [{ "kid": "a 1", "x": product_key(4) }] }),
            serde_json::json!({ "keys": [{ "kid": "a1", "x": product_key(4) }, { "kid": "a1", "x": product_key(5) }] }),
            serde_json::json!({ "keys": key, "tokens": { "a": ["x"] } }),
            serde_json::json!({ "keys": key, "tokens": { "c": ["x"] } }),
            serde_json::json!({ "keys": key, "tokens": { "nobody": ["x"] } }),
            serde_json::json!({ "keys": key, "tokens": { "b": [] } }),
            serde_json::json!({ "keys": key, "tokens": { "b": ["Bad Scope"] } }),
            serde_json::json!({ "keys": key, "unknown": true }),
        ] {
            assert!(
                matches!(err(entry(product.clone())), Some(ConfigError::Clients(_))),
                "{product}"
            );
        }
        // Without a product entry, a client still needs a redirect URI.
        let no_redirect = serde_json::json!([{ "client_id": "c", "name": "C", "skin": "slug", "redirect_uris": [] }]);
        assert!(matches!(err(no_redirect), Some(ConfigError::Clients(_))));
    }

    #[test]
    fn refuses_unsafe_settings() {
        let err = |overrides: &[(&str, &str)]| Config::from_lookup(lookup(overrides)).err();
        assert_eq!(
            err(&[("AIS_ISSUER", "http://auth.aiaiaiai.org")]),
            Some(ConfigError::Issuer)
        );
        assert_eq!(
            err(&[("AIS_SIGNING_KEY", "short")]),
            Some(ConfigError::SigningKey)
        );
        assert_eq!(
            err(&[("AIS_SECRET", "short")]),
            Some(ConfigError::ShortSecret("AIS_SECRET"))
        );
        assert_eq!(
            err(&[("AIS_PASSWORD_PEPPER", "short")]),
            Some(ConfigError::ShortSecret("AIS_PASSWORD_PEPPER"))
        );
        assert!(matches!(
            err(&[("AIS_CLIENTS", "[]")]),
            Some(ConfigError::Clients(_))
        ));
        let http_redirect = r#"[{"client_id":"x","name":"X","skin":"slug","redirect_uris":["http://x.example/cb"],"secret_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]"#;
        assert!(matches!(
            err(&[("AIS_CLIENTS", http_redirect)]),
            Some(ConfigError::Clients(_))
        ));
        let missing: &[(&str, &str)] = &[("AIS_SECRET", "")];
        assert_eq!(err(missing), Some(ConfigError::Missing("AIS_SECRET")));
    }
}
