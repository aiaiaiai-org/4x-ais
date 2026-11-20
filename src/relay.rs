// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Calls Prism Hub relays to AIS (`hub.v1`): the bearer is a product token AIS
//! itself issued for the audience `ais`, to a relay acting for another
//! registered product. Hub has already checked that product's grant for the
//! operation; AIS checks the token, its scope, and who is acting.

use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use serde::Deserialize;

use crate::{issuer::AppState, product_token::AIS_AUDIENCE};

const MAX_TOKEN_BYTES: usize = 4096;

/// Who is asking: the relay that presented the token and the product it acts
/// for.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Caller {
    pub(crate) relay: String,
    pub(crate) asker: String,
}

#[derive(Deserialize)]
struct TokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
struct Act {
    sub: String,
}

#[derive(Deserialize)]
struct TokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    scope: String,
    #[serde(default)]
    act: Option<Act>,
}

fn decode<T: for<'a> Deserialize<'a>>(part: &str) -> Option<T> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

/// A product token AIS itself issued for `AIS_AUDIENCE`, holding `scope`, to
/// a relay acting for another registered product.
pub(crate) fn caller(
    state: &AppState,
    headers: &HeaderMap,
    now: u64,
    scope: &str,
) -> Option<Caller> {
    let token = headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let header: TokenHeader = decode(header)?;
    if header.alg != "EdDSA" || header.typ != "at+jwt" || header.kid != state.config.key_id {
        return None;
    }
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?).ok()?;
    let signed = &token[..token.rfind('.')?];
    state
        .config
        .signing_key
        .verifying_key()
        .verify_strict(signed.as_bytes(), &signature)
        .ok()?;
    let claims: TokenClaims = decode(payload)?;
    if claims.iss != state.config.issuer_id()
        || claims.aud != AIS_AUDIENCE
        || claims.exp <= now
        || !claims.scope.split(' ').any(|held| held == scope)
    {
        return None;
    }
    // Only a relay asks, and only for a registered product other than itself.
    let relay = state.config.clients.get(&claims.sub)?;
    if !relay.product.as_ref().is_some_and(|product| product.relay) {
        return None;
    }
    let asker = claims.act?.sub;
    let asking = state.config.clients.get(&asker)?;
    if asking.product.is_none() || asker == claims.sub {
        return None;
    }
    Some(Caller {
        relay: claims.sub,
        asker,
    })
}

/// The exact product using a service-issued token for itself, **not** a
/// delegated Prism relay. Keep this separate from \`caller\`: relay tokens
/// require an \`act\` claim, but direct product tokens must never carry one.
pub(crate) fn direct_product(
    state: &AppState,
    headers: &HeaderMap,
    now: u64,
    scope: &str,
    expected_client: &str,
) -> bool {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() <= MAX_TOKEN_BYTES)
    else {
        return false;
    };
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(header) = decode::<TokenHeader>(header) else {
        return false;
    };
    if header.alg != "EdDSA" || header.typ != "at+jwt" || header.kid != state.config.key_id {
        return false;
    }
    let Some(signature) = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|value| Signature::from_slice(&value).ok())
    else {
        return false;
    };
    let Some(signed) = token.rsplit_once('.').map(|(signed, _)| signed) else {
        return false;
    };
    if state
        .config
        .signing_key
        .verifying_key()
        .verify_strict(signed.as_bytes(), &signature)
        .is_err()
    {
        return false;
    }
    let Some(claims) = decode::<TokenClaims>(payload) else {
        return false;
    };
    claims.iss == state.config.issuer_id()
        && claims.aud == AIS_AUDIENCE
        && claims.exp > now
        && claims.sub == expected_client
        && claims.act.is_none()
        && claims.scope.split(' ').any(|held| held == scope)
        && state
            .config
            .clients
            .get(expected_client)
            .is_some_and(|client| client.product.is_some())
}
