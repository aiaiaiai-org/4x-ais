// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! The family link (`hub.v1`, docs/hub-protocol.md): which account a person
//! holds in a product. For 0x1 that account is the Bond. A product reports
//! its own accounts (`accounts.put`); another product asks once which account
//! a person holds (`people.link`) and from then on talks to that product by
//! the account. Both arrive through Prism Hub. AIS keeps the link and nothing
//! about the account: no balance, no state.

use std::str::FromStr as _;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use nilxone_contracts::PubDress;
use serde::Deserialize;

use crate::{
    issuer::{AppState, no_store, now, token_error},
    relay::caller,
    store::LinkReport,
};

/// The scope a relay's token must hold to report a product's account.
pub const ACCOUNTS_PUT_SCOPE: &str = "accounts.put";
/// The scope a relay's token must hold to ask which account a person holds.
pub const LINK_READ_SCOPE: &str = "link.read";
/// How far ahead of AIS's clock a report may be dated.
const CLOCK_LEEWAY: u64 = 60;
const MAX_ACCOUNT_BYTES: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountReport {
    /// The reporting product's own pairwise subject for the person.
    subject: String,
    /// The product's stable account reference (for 0x1, the Bond).
    account: String,
    /// The account's current public address, for display.
    pub_dress: String,
    /// When the product made this report, in seconds since the epoch.
    as_of: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkQuery {
    /// The asking product's own pairwise subject for the person.
    subject: String,
    /// The product whose account the asker wants to know.
    product: String,
}

pub(crate) fn subject_ok(subject: &str) -> bool {
    // A pairwise subject is 32 bytes, unpadded base64url.
    subject.len() == 43
        && subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn account_ok(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= MAX_ACCOUNT_BYTES
        && account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn unavailable(error: &crate::store::StoreError) -> Response {
    tracing::error!(%error, "family link storage failed");
    token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
}

/// `POST /family/accounts` (`accounts.put`): a product reports which of its
/// accounts a person holds. A product writes only its own accounts.
pub(crate) async fn put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<AccountReport>,
) -> Response {
    let now = now();
    let Some(caller) = caller(&state, &headers, now, ACCOUNTS_PUT_SCOPE) else {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if !subject_ok(&report.subject)
        || !account_ok(&report.account)
        || PubDress::from_str(&report.pub_dress).is_err()
        || report.as_of > now + CLOCK_LEEWAY
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let person = match state
        .store
        .subject_for(&caller.asker, &report.subject)
        .await
    {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "unknown_subject"),
        Err(error) => return unavailable(&error),
    };
    // The product of the account is the product that reports it, always.
    match state
        .store
        .put_link(
            &person,
            &caller.asker,
            &report.account,
            &report.pub_dress,
            report.as_of,
        )
        .await
    {
        Ok(LinkReport::Stored) => {
            no_store(StatusCode::OK, serde_json::json!({ "status": "stored" }))
        }
        Ok(LinkReport::Stale) => no_store(StatusCode::OK, serde_json::json!({ "status": "stale" })),
        Ok(LinkReport::AccountTaken) => token_error(StatusCode::CONFLICT, "account_taken"),
        Err(error) => unavailable(&error),
    }
}

/// `POST /family/link` (`people.link`): which account a person holds in
/// another product. The answer names the account and its public address,
/// never the other product's pairwise subject.
pub(crate) async fn link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<LinkQuery>,
) -> Response {
    let now = now();
    let Some(caller) = caller(&state, &headers, now, LINK_READ_SCOPE) else {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let product_known = state
        .config
        .clients
        .get(&query.product)
        .is_some_and(|client| client.product.is_some());
    if !subject_ok(&query.subject) || !product_known || query.product == caller.asker {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let person = match state.store.subject_for(&caller.asker, &query.subject).await {
        Ok(Some(person)) => person,
        Ok(None) => return token_error(StatusCode::NOT_FOUND, "unknown"),
        Err(error) => return unavailable(&error),
    };
    match state.store.link_for(&person, &query.product).await {
        Ok(Some(found)) => no_store(
            StatusCode::OK,
            serde_json::json!({
                "sub": query.subject,
                "accounts": { query.product: {
                    "account": found.account,
                    "pub_dress": found.label,
                    "as_of": found.as_of,
                }},
            }),
        ),
        Ok(None) => token_error(StatusCode::NOT_FOUND, "unknown"),
        Err(error) => unavailable(&error),
    }
}
