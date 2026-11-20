// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Read-only, explicitly scoped Telegram provider-link evidence for 0x1 Core.
//! A trusted 0x1 host must FIRST authenticate the Telegram adapter and verify
//! the genuine sender. AIS only resolves its already recorded binding; no
//! link, Bond, session or permission is created by this route.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    crypto::{random_token, sign_jwt_typed},
    issuer::{AppState, no_store, now, token_error},
    relay::direct_product,
};

const TARGET: &str = "0x1";
const SCOPE: &str = "telegram.identity.resolve";
const EVIDENCE_TTL: u64 = 120;

/// Scope-limited request from a verified 0x1 product host. The nonce is an
/// unpredictable request binding, not an authorization credential.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveRequest {
    telegram_id: i64,
    nonce: String,
}

fn valid_nonce(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl ResolveRequest {
    fn valid(&self) -> bool {
        self.telegram_id > 0 && valid_nonce(&self.nonce)
    }
}

/// POST /family/telegram-identity. The client MUST acquire a direct AIS
/// client_credentials token for audience=ais and scope=telegram.identity.resolve
/// using its registered asymmetric key. A Prism relay token is not accepted.
///
/// The request's Telegram user ID is verified by the 0x1 host, not by AIS.
/// The response is a short-lived, nonce-bound JWT carrying the 0x1 pairwise
/// subject, never a raw Telegram ID or a product-session credential.
pub(crate) async fn resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveRequest>,
) -> Response {
    let now = now();
    if !direct_product(&state, &headers, now, SCOPE, TARGET) {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    if !request.valid() {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let person = match state.store.subject_for_telegram(request.telegram_id).await {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "telegram_unlinked"),
        Err(error) => {
            tracing::error!(%error, "Telegram provider-link lookup failed");
            return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };
    // AIS may have a linked Telegram provider but no 0x1 product account.
    // A provider link alone must never imply a Bond or product capability.
    match state.store.link_for(&person, TARGET).await {
        Ok(Some(_)) => {}
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "bond_unlinked"),
        Err(error) => {
            tracing::error!(%error, "Telegram product-link lookup failed");
            return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    }
    let Some(jti) = random_token(16) else {
        return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let claims = json!({
        "iss": state.config.issuer_id(),
        "aud": TARGET,
        "sub": state.keys.pairwise_subject(TARGET, &person),
        "azp": TARGET,
        "provider": "telegram",
        "purpose": SCOPE,
        "nonce": request.nonce,
        "iat": now,
        "exp": now + EVIDENCE_TTL,
        "jti": jti,
    });
    let proof = sign_jwt_typed(
        &state.config.signing_key,
        &state.config.key_id,
        "provider-evidence+jwt",
        &claims,
    );
    no_store(
        StatusCode::OK,
        json!({ "proof": proof, "expires_in": EVIDENCE_TTL }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_strict_and_requires_nonce_bound_to_request() {
        let valid = serde_json::from_str::<ResolveRequest>(
            r#"{"telegram_id":42,"nonce":"abcdefghijklmnopABCDEFGHIJKLMNOP"}"#,
        )
        .unwrap();
        assert!(valid.valid());

        for value in [
            r#"{"telegram_id":0,"nonce":"abcdefghijklmnopABCDEFGHIJKLMNOP"}"#,
            r#"{"telegram_id":-1,"nonce":"abcdefghijklmnopABCDEFGHIJKLMNOP"}"#,
            r#"{"telegram_id":42,"nonce":"too-short"}"#,
            r#"{"telegram_id":42,"nonce":"abcdefghijklmnopABCDEFGHIJKLMNOP!"}"#,
        ] {
            let request = serde_json::from_str::<ResolveRequest>(value).unwrap();
            assert!(!request.valid());
        }
        assert!(
            serde_json::from_str::<ResolveRequest>(
                r#"{"telegram_id":42,"nonce":"abcdefghijklmnopABCDEFGHIJKLMNOP","bond":"0x0sky"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_scope_and_lifetime_are_narrow() {
        assert_eq!(TARGET, "0x1");
        assert_eq!(SCOPE, "telegram.identity.resolve");
        assert_eq!(EVIDENCE_TTL, 120);
    }
}
