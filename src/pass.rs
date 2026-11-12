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
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use crate::{
    crypto::{random_token, sign_jwt_typed},
    family::subject_ok,
    issuer::{AppState, no_store, now, token_error},
    relay::caller,
};

/// How long a pass is good for: the life of an order's authorization.
pub const PASS_TTL: u64 = 15 * 60;
/// The scope a relay's token must hold to ask for a pass.
pub const PASS_SCOPE: &str = "pass.issue";
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

/// `POST /family/pass`.
pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PassRequest>,
) -> Response {
    let now = now();
    let Some(caller) = caller(&state, &headers, now, PASS_SCOPE) else {
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
