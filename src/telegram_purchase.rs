// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Resolve a verified Telegram binding in AIS and issue a permit for one
//! checkout. The issuer still verifies the offer and settles its own wallet.

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
    family::subject_ok,
    issuer::{AppState, no_store, now, token_error},
    product_token::grant_scopes,
    relay::{Caller, caller},
    store::{LinkReport, StoreError},
};

const LINK_SCOPE: &str = "telegram.link.put";
const ORDER_SCOPE: &str = "telegram.special.purchase";
const TARGET: &str = "0x1";
const SKU: &str = "0x1_special_1m";
const PERMIT_TTL: u64 = 120;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Link {
    subject: String,
    // Removal is explicit null. An absent field is an invalid report.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    telegram_id: Option<i64>,
    revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Order {
    telegram_id: i64,
    order_id: String,
    sku: String,
    quantity: u8,
    price_id: i64,
    amount_minor: i64,
}

fn scoped_caller(state: &AppState, headers: &HeaderMap, now: u64, scope: &str) -> Option<Caller> {
    let actor = caller(state, headers, now, scope)?;
    let product = state.config.clients.get(&actor.asker)?.product.as_ref()?;
    grant_scopes(product, &actor.relay, Some(scope)).ok()?;
    Some(actor)
}

fn unavailable(error: StoreError) -> Response {
    tracing::error!(%error, "Telegram identity operation failed");
    token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
}

pub(crate) async fn report_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<Link>,
) -> Response {
    let Some(actor) = scoped_caller(&state, &headers, now(), LINK_SCOPE) else {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if actor.asker != TARGET {
        return token_error(StatusCode::FORBIDDEN, "invalid_actor");
    }
    if !subject_ok(&report.subject)
        || report.telegram_id.is_some_and(|id| id <= 0)
        || report.revision <= 0
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let subject = match state.store.subject_for(&actor.asker, &report.subject).await {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "unknown_subject"),
        Err(error) => return unavailable(error),
    };
    match state
        .store
        .put_telegram_link(&subject, report.telegram_id, report.revision)
        .await
    {
        Ok(LinkReport::Stored) => no_store(StatusCode::OK, json!({"status": "stored"})),
        Ok(LinkReport::Stale) => no_store(StatusCode::OK, json!({"status": "stale"})),
        Ok(LinkReport::AccountTaken) => token_error(StatusCode::CONFLICT, "account_taken"),
        Err(error) => unavailable(error),
    }
}

pub(crate) async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(order): Json<Order>,
) -> Response {
    let now = now();
    let Some(actor) = scoped_caller(&state, &headers, now, ORDER_SCOPE) else {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if order.telegram_id <= 0
        || order.sku != SKU
        || order.quantity != 1
        || order.price_id <= 0
        || order.amount_minor <= 0
        || order.order_id.is_empty()
        || order.order_id.len() > 128
        || !order
            .order_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let person = match state.store.subject_for_telegram(order.telegram_id).await {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "telegram_unlinked"),
        Err(error) => return unavailable(error),
    };
    match state.store.link_for(&person, TARGET).await {
        Ok(Some(_)) => {}
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "bond_unlinked"),
        Err(error) => return unavailable(error),
    }
    let sub = state.keys.pairwise_subject(TARGET, &person);
    let Some(jti) = random_token(16) else {
        return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let claims = json!({
        "iss": state.config.issuer_id(),
        "aud": TARGET,
        "sub": sub,
        "azp": actor.asker,
        "purpose": "telegram.special.purchase",
        "order_id": order.order_id,
        "telegram_id": order.telegram_id,
        "sku": order.sku,
        "quantity": order.quantity,
        "price_id": order.price_id,
        "amount_minor": order.amount_minor,
        "denomination": "seeds",
        "iat": now,
        "exp": now + PERMIT_TTL,
        "jti": jti,
    });
    let permit = sign_jwt_typed(
        &state.config.signing_key,
        &state.config.key_id,
        "purchase+jwt",
        &claims,
    );
    no_store(
        StatusCode::OK,
        json!({"permit": permit, "expires_in": PERMIT_TTL}),
    )
}
