// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Person passes (`hub.v1`, docs/hub-protocol.md): a short signed note that
//! says "for this one operation, this person is product B's `sub` X", sealed
//! for B. Only a relay (Prism Hub) asks, on behalf of the product that names
//! the person by its own pairwise subject, and AIS answers only for a person
//! it gave that product that subject.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use serde::Deserialize;

use crate::{
    crypto::{random_token, sign_jwt_typed},
    issuer::{AppState, no_store, now, token_error},
    product_token::AIS_AUDIENCE,
};

/// How long a pass is good for: the life of an order's authorization.
pub const PASS_TTL: u64 = 15 * 60;
/// The scope a relay's token must hold to ask for a pass.
pub const PASS_SCOPE: &str = "pass.issue";
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_ORDER_ID_BYTES: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassRequest {
    /// The asking product's own pairwise subject for the person.
    subject: String,
    /// The product the pass is for.
    audience: String,
    /// `claims`, or `order:<order id>`.
    purpose: String,
}

/// Who is asking: the relay that presented the token and the product it acts
/// for.
#[derive(Debug, Eq, PartialEq)]
struct Caller {
    relay: String,
    asker: String,
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

/// A product token AIS itself issued for `AIS_AUDIENCE`, to a relay acting
/// for another registered product.
fn caller(state: &AppState, headers: &HeaderMap, now: u64) -> Option<Caller> {
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
        || !claims.scope.split(' ').any(|scope| scope == PASS_SCOPE)
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

fn purpose_ok(purpose: &str) -> bool {
    if purpose == "claims" {
        return true;
    }
    purpose.strip_prefix("order:").is_some_and(|id| {
        !id.is_empty()
            && id.len() <= MAX_ORDER_ID_BYTES
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

fn subject_ok(subject: &str) -> bool {
    // A pairwise subject is 32 bytes, unpadded base64url.
    subject.len() == 43
        && subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// `POST /family/pass`.
pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PassRequest>,
) -> Response {
    let now = now();
    let Some(caller) = caller(&state, &headers, now) else {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let audience_is_product = state
        .config
        .clients
        .get(&request.audience)
        .is_some_and(|client| client.product.is_some());
    if !audience_is_product
        || request.audience == caller.asker
        || !purpose_ok(&request.purpose)
        || !subject_ok(&request.subject)
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let person = match state
        .store
        .subject_for(&caller.asker, &request.subject)
        .await
    {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "unknown_subject"),
        Err(error) => {
            tracing::error!(%error, "reading an issued subject failed");
            return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };
    let sub = state.keys.pairwise_subject(&request.audience, &person);
    // The audience may later name this person by the subject in the pass.
    if let Err(error) = state
        .store
        .remember_subject(&request.audience, &sub, &person)
        .await
    {
        tracing::error!(%error, "remembering an issued subject failed");
        return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let Some(jti) = random_token(16) else {
        return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let claims = serde_json::json!({
        "iss": state.config.issuer_id(),
        "aud": request.audience,
        "sub": sub,
        "azp": caller.asker,
        "purpose": request.purpose,
        "iat": now,
        "exp": now + PASS_TTL,
        "jti": jti,
    });
    tracing::info!(relay = %caller.relay, asker = %caller.asker, audience = %request.audience, "person pass issued");
    let pass = sign_jwt_typed(
        &state.config.signing_key,
        &state.config.key_id,
        "pass+jwt",
        &claims,
    );
    no_store(
        StatusCode::OK,
        serde_json::json!({ "pass": pass, "expires_in": PASS_TTL }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purpose_is_claims_or_one_order() {
        assert!(purpose_ok("claims"));
        assert!(purpose_ok("order:ord_01JD7Q8M3K6ZB9R2T4V5W7X8Y0"));
        assert!(!purpose_ok("order:"));
        assert!(!purpose_ok("order:a b"));
        assert!(!purpose_ok(&format!("order:{}", "a".repeat(129))));
        assert!(!purpose_ok("anything"));
    }

    #[test]
    fn a_subject_has_the_shape_ais_gives() {
        assert!(subject_ok(&"a".repeat(43)));
        assert!(!subject_ok(&"a".repeat(42)));
        assert!(!subject_ok(&format!("{}=", "a".repeat(42))));
    }
}
