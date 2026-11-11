// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Runtime configuration. Every secret arrives in the environment from the
//! producer's envelope; infra only carries it (docs/runtime.md).

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;

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
}

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
        if record.redirect_uris.is_empty() {
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
        Ok(Self {
            client_id: record.client_id,
            name: record.name,
            skin: record.skin,
            redirect_uris: record.redirect_uris,
            secret_sha256,
            pub_dress_scope: record.pub_dress,
        })
    }
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
