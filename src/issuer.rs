// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! The OpenID Connect issuer at `auth.aiaiaiai.org`: authorization code with
//! PKCE (S256 only), a pairwise `sub` per client and EdDSA `id_token`s. The
//! token contract is the one `nilx-one/core`'s `aiaiaiai_sign_in` verifies.

use std::{
    collections::HashMap,
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nilxone_contracts::{PubDress, PubDressLabel};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use url::Url;

use crate::{
    config::{Client, Config, Skin},
    crypto::{Keys, random_token, sign_jwt},
    limiter::Limiter,
    page::{self, Language, Message, Step, View},
    password::{PasswordEngine, PolicyError},
    store::{DISCRIMINATORS, Identity, Registration, Store},
};

/// Binds an authorization request to the browser that opened it, so a form
/// posted from another site cannot finish someone else's sign-in.
const BROWSER_COOKIE: &str = "__Host-ais_authz";
/// Remembers the last address on this origin. A hint, never authentication.
const HINT_COOKIE: &str = "__Host-ais_hint";
const REQUEST_DOMAIN: &str = "authorization-request";
const ASSIGNMENT_DOMAIN: &str = "address-assignment";
const HINT_DOMAIN: &str = "address-hint";
const REQUEST_TTL: u64 = 15 * 60;
const CODE_TTL: u64 = 60;
const ID_TOKEN_TTL: u64 = 5 * 60;
const HINT_TTL: u64 = 180 * 24 * 60 * 60;
const MAX_PARAMETER_BYTES: usize = 512;
const MAX_PENDING_CODES: usize = 10_000;
const STYLESHEET: &str = include_str!("../static/auth.css");

/// A code waiting for its single exchange. The pairwise subject is fixed at
/// sign-in, so nothing that happens before the exchange changes who it names.
#[derive(Clone)]
struct PendingCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    nonce: String,
    subject: String,
    pub_dress: Option<String>,
    auth_time: u64,
    expires_at: u64,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    keys: Keys,
    store: Store,
    passwords: PasswordEngine,
    limiter: Limiter,
    dummy_hash: Arc<str>,
    // Codes live sixty seconds in this process; a restart only means the
    // person signs in again.
    codes: Arc<Mutex<HashMap<[u8; 32], PendingCode>>>,
}

pub fn router(config: Config, store: Store) -> Router {
    let passwords = PasswordEngine::new(&config.password_pepper);
    let dummy_hash = passwords
        .hash("ais constant-shape dummy password")
        .expect("password hashing must initialize");
    let state = AppState {
        keys: Keys::derive(&config.secret),
        config: Arc::new(config),
        store,
        passwords,
        limiter: Limiter::default(),
        dummy_hash: Arc::from(dummy_hash),
        codes: Arc::default(),
    };
    Router::new()
        .route("/", get(|| async { page::landing() }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/static/auth.css", get(stylesheet))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", get(authorize).post(submit))
        .route("/token", post(token))
        .with_state(state)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

async fn stylesheet() -> Response {
    let mut response = STYLESHEET.into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn public_json(value: serde_json::Value) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

async fn discovery(State(state): State<AppState>) -> Response {
    let issuer = state.config.issuer_id();
    public_json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "pub_dress"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "pub_dress"],
    }))
}

async fn jwks(State(state): State<AppState>) -> Response {
    let key = state.config.signing_key.verifying_key();
    public_json(serde_json::json!({ "keys": [{
        "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
        "kid": state.config.key_id,
        "x": URL_SAFE_NO_PAD.encode(key.as_bytes()),
    }]}))
}

// ---------------------------------------------------------------------------
// The authorization request
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// A validated request, carried through the page as a sealed form field.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuthorizationRequest {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    pub_dress_scope: bool,
    browser: String,
    expires_at: u64,
}

#[derive(Deserialize, Serialize)]
struct Assignment {
    pub_dress: String,
    browser: String,
}

#[derive(Deserialize, Serialize)]
struct Hint {
    pub_dress: String,
    expires_at: u64,
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name && !value.is_empty()).then(|| value.to_owned())
        })
}

fn cookie(name: &str, value: &str, max_age: u64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax")
}

fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(SET_COOKIE, value);
    }
}

fn on_issuer_host(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(&state.config.issuer_host()))
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn redirect_error(redirect_uri: &str, error: &str, client_state: &str) -> Response {
    let Ok(mut location) = Url::parse(redirect_uri) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    {
        let mut query = location.query_pairs_mut();
        query.append_pair("error", error);
        if !client_state.is_empty() && client_state.len() <= MAX_PARAMETER_BYTES {
            query.append_pair("state", client_state);
        }
    }
    redirect(location.as_str())
}

fn origin_of(uri: &str) -> String {
    Url::parse(uri)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default()
}

async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let language = Language::from(&headers);
    if !on_issuer_host(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Until client and redirect are known, nothing may redirect anywhere.
    let Some(client) = query
        .client_id
        .as_deref()
        .and_then(|id| state.config.clients.get(id))
        .cloned()
    else {
        return page::error_page(language, StatusCode::BAD_REQUEST, Message::UnknownClient);
    };
    let Some(redirect_uri) = query
        .redirect_uri
        .clone()
        .filter(|uri| client.redirect_uris.iter().any(|allowed| allowed == uri))
    else {
        return page::error_page(language, StatusCode::BAD_REQUEST, Message::UnknownClient);
    };
    let client_state = query.state.clone().unwrap_or_default();
    let fail = |error: &str| redirect_error(&redirect_uri, error, &client_state);
    if client_state.is_empty() || client_state.len() > MAX_PARAMETER_BYTES {
        return fail("invalid_request");
    }
    if query.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type");
    }
    let scopes: Vec<&str> = query
        .scope
        .as_deref()
        .unwrap_or("")
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .collect();
    if !scopes.contains(&"openid")
        || scopes
            .iter()
            .any(|scope| !matches!(*scope, "openid" | "pub_dress"))
        || (scopes.contains(&"pub_dress") && !client.pub_dress_scope)
    {
        return fail("invalid_scope");
    }
    let Some(nonce) = query
        .nonce
        .clone()
        .filter(|value| !value.is_empty() && value.len() <= MAX_PARAMETER_BYTES)
    else {
        return fail("invalid_request");
    };
    let Some(code_challenge) = query.code_challenge.clone().filter(|value| {
        value.len() == 43
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) else {
        return fail("invalid_request");
    };
    if query.code_challenge_method.as_deref() != Some("S256") {
        return fail("invalid_request");
    }
    let Some(browser) = random_token(24) else {
        return page::error_page(
            language,
            StatusCode::SERVICE_UNAVAILABLE,
            Message::Unavailable,
        );
    };
    let now = now();
    let request = AuthorizationRequest {
        client_id: client.client_id.clone(),
        redirect_uri,
        state: client_state,
        nonce,
        code_challenge,
        pub_dress_scope: scopes.contains(&"pub_dress"),
        browser: browser.clone(),
        expires_at: now + REQUEST_TTL,
    };
    let signed = state.keys.seal(REQUEST_DOMAIN, &request);
    let hint = read_cookie(&headers, HINT_COOKIE)
        .and_then(|value| state.keys.open::<Hint>(HINT_DOMAIN, &value))
        .filter(|hint| hint.expires_at > now)
        .and_then(|hint| PubDress::from_str(&hint.pub_dress).ok());
    let view = View {
        language,
        skin: client.skin,
        product: &client.name,
        signed: &signed,
        redirect_origin: &origin_of(&request.redirect_uri),
        message: None,
    };
    let (prefix, slug) = hint.as_ref().map_or(('0', ""), |address| {
        (address.discriminator(), address.slug())
    });
    let mut response = page::render(&view, StatusCode::OK, Step::Identify { prefix, slug });
    append_cookie(
        &mut response,
        &cookie(BROWSER_COOKIE, &browser, REQUEST_TTL),
    );
    response
}

// ---------------------------------------------------------------------------
// The page: identify, then sign in or create
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct SubmitForm {
    request: String,
    step: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    pub_dress: String,
    #[serde(default)]
    assignment: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_confirm: String,
}

/// Everything one submitted step needs to answer.
struct Ctx<'a> {
    state: &'a AppState,
    request: AuthorizationRequest,
    client: Client,
    language: Language,
    signed: &'a str,
    redirect_origin: String,
    now: u64,
    source: String,
}

impl Ctx<'_> {
    fn render(&self, status: StatusCode, message: Option<Message>, step: Step<'_>) -> Response {
        let view = View {
            language: self.language,
            skin: self.client.skin,
            product: &self.client.name,
            signed: self.signed,
            redirect_origin: &self.redirect_origin,
            message,
        };
        page::render(&view, status, step)
    }

    fn identify_again(
        &self,
        status: StatusCode,
        message: Message,
        prefix: char,
        slug: &str,
    ) -> Response {
        self.render(status, Some(message), Step::Identify { prefix, slug })
    }

    fn assignment(&self, pub_dress: &PubDress) -> String {
        self.state.keys.seal(
            ASSIGNMENT_DOMAIN,
            &Assignment {
                pub_dress: pub_dress.as_str().to_owned(),
                browser: self.request.browser.clone(),
            },
        )
    }

    fn register_step(
        &self,
        pub_dress: &PubDress,
        message: Option<Message>,
        status: StatusCode,
    ) -> Response {
        let assignment = self.assignment(pub_dress);
        self.render(
            status,
            message,
            Step::Register {
                pub_dress: pub_dress.as_str(),
                slug: pub_dress.slug(),
                assignment: &assignment,
            },
        )
    }

    /// The sign-in step for an address as it was registered, which may differ
    /// in case from what the person typed.
    fn sign_in_as(&self, identity: &Identity) -> Response {
        let slug = PubDress::from_str(&identity.pub_dress)
            .map(|address| address.slug().to_owned())
            .unwrap_or_default();
        self.sign_in_step(&identity.pub_dress, &slug, None, StatusCode::OK)
    }

    fn sign_in_step(
        &self,
        pub_dress: &str,
        slug: &str,
        message: Option<Message>,
        status: StatusCode,
    ) -> Response {
        self.render(status, message, Step::SignIn { pub_dress, slug })
    }
}

/// The client address as the edge saw it. Only the last hop is the edge's own:
/// anything before it arrived from the client and is whatever the client
/// wanted, so trusting the first hop would let anyone pick their own limit key.
fn request_source(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .unwrap_or("unknown")
        .to_owned()
}

/// Whether the address has a public label. `PubDress` accepts some spellings
/// (punctuation, edge hyphens) that no label can carry; those are invalid
/// input, not taken addresses.
fn representable(address: &PubDress) -> bool {
    PubDressLabel::stem(address).is_ok()
}

fn parse_prefix(value: &str) -> Option<char> {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some(prefix), None) if DISCRIMINATORS.contains(&prefix) => Some(prefix),
        _ => None,
    }
}

async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SubmitForm>,
) -> Response {
    let language = Language::from(&headers);
    if !on_issuer_host(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = now();
    let Some(request) = state
        .keys
        .open::<AuthorizationRequest>(REQUEST_DOMAIN, &form.request)
        .filter(|request| request.expires_at > now)
        .filter(|request| {
            read_cookie(&headers, BROWSER_COOKIE).is_some_and(|browser| {
                bool::from(browser.as_bytes().ct_eq(request.browser.as_bytes()))
            })
        })
    else {
        return page::error_page(language, StatusCode::BAD_REQUEST, Message::Expired);
    };
    let Some(client) = state.config.clients.get(&request.client_id).cloned() else {
        return page::error_page(language, StatusCode::BAD_REQUEST, Message::UnknownClient);
    };
    let ctx = Ctx {
        state: &state,
        redirect_origin: origin_of(&request.redirect_uri),
        request,
        client,
        language,
        signed: &form.request,
        now,
        source: request_source(&headers),
    };
    match form.step.as_str() {
        "identify" => identify(&ctx, &form).await,
        "choose" => choose(&ctx, &form).await,
        "sign_in" => sign_in(&ctx, &form).await,
        "register" => register(&ctx, &form).await,
        _ => page::error_page(language, StatusCode::BAD_REQUEST, Message::Expired),
    }
}

async fn identify(ctx: &Ctx<'_>, form: &SubmitForm) -> Response {
    let slug = form.slug.trim();
    let prefix = match ctx.client.skin {
        Skin::Cell => parse_prefix(&form.prefix),
        // The prefix plays no part in whether a slug is valid.
        Skin::Slug => Some('0'),
    };
    let Some(candidate) = prefix
        .and_then(|prefix| PubDress::from_str(&format!("0x{prefix}{slug}")).ok())
        .filter(representable)
    else {
        return ctx.identify_again(
            StatusCode::UNPROCESSABLE_ENTITY,
            Message::InvalidAddress,
            '0',
            slug,
        );
    };
    if !ctx
        .state
        .limiter
        .allow(&format!("resolve:{}", ctx.source), ctx.now, 60, 60)
    {
        return ctx.identify_again(
            StatusCode::TOO_MANY_REQUESTS,
            Message::RateLimited,
            candidate.discriminator(),
            slug,
        );
    }
    let unavailable = || {
        page::error_page(
            ctx.language,
            StatusCode::SERVICE_UNAVAILABLE,
            Message::Unavailable,
        )
    };
    match ctx.client.skin {
        Skin::Cell => match ctx.state.store.find(&candidate).await {
            Ok(Some(identity)) => ctx.sign_in_as(&identity),
            Ok(None) => match ctx.state.store.is_free(&candidate).await {
                Ok(true) => ctx.register_step(&candidate, None, StatusCode::OK),
                Ok(false) => ctx.identify_again(
                    StatusCode::CONFLICT,
                    Message::Taken,
                    candidate.discriminator(),
                    slug,
                ),
                Err(_) => unavailable(),
            },
            Err(_) => unavailable(),
        },
        Skin::Slug => match ctx.state.store.find_by_slug(candidate.slug()).await {
            Ok(found) if found.is_empty() => {
                match ctx.state.store.free_prefix_for(candidate.slug()).await {
                    Ok(Some(assigned)) => ctx.register_step(&assigned, None, StatusCode::OK),
                    Ok(None) => {
                        ctx.identify_again(StatusCode::CONFLICT, Message::NoFreePrefix, '0', slug)
                    }
                    Err(_) => unavailable(),
                }
            }
            Ok(found) if found.len() == 1 => ctx.sign_in_as(&found[0]),
            Ok(found) => {
                let prefixes: Vec<char> = found
                    .iter()
                    .filter_map(|identity| PubDress::from_str(&identity.pub_dress).ok())
                    .map(|address| address.discriminator())
                    .collect();
                ctx.render(
                    StatusCode::OK,
                    Some(Message::ChoosePrefix),
                    Step::ChoosePrefix {
                        slug: candidate.slug(),
                        prefixes: &prefixes,
                    },
                )
            }
            Err(_) => unavailable(),
        },
    }
}

/// `slug` products: the person picked which of several addresses is theirs.
async fn choose(ctx: &Ctx<'_>, form: &SubmitForm) -> Response {
    let slug = form.slug.trim();
    let Some(candidate) = parse_prefix(&form.prefix)
        .and_then(|prefix| PubDress::from_str(&format!("0x{prefix}{slug}")).ok())
        .filter(representable)
    else {
        return ctx.identify_again(
            StatusCode::UNPROCESSABLE_ENTITY,
            Message::InvalidAddress,
            '0',
            slug,
        );
    };
    // The same lookup budget as `identify`: otherwise this step would probe
    // which prefixes of a slug are taken without limit.
    if !ctx
        .state
        .limiter
        .allow(&format!("resolve:{}", ctx.source), ctx.now, 60, 60)
    {
        return ctx.identify_again(
            StatusCode::TOO_MANY_REQUESTS,
            Message::RateLimited,
            '0',
            slug,
        );
    }
    match ctx.state.store.find(&candidate).await {
        Ok(Some(identity)) => ctx.sign_in_as(&identity),
        Ok(None) => ctx.identify_again(
            StatusCode::UNPROCESSABLE_ENTITY,
            Message::InvalidCredentials,
            '0',
            slug,
        ),
        Err(_) => page::error_page(
            ctx.language,
            StatusCode::SERVICE_UNAVAILABLE,
            Message::Unavailable,
        ),
    }
}

async fn sign_in(ctx: &Ctx<'_>, form: &SubmitForm) -> Response {
    let Some((pub_dress, label)) = PubDress::from_str(&form.pub_dress)
        .ok()
        .and_then(|address| {
            let label = PubDressLabel::stem(&address).ok()?.as_str().to_owned();
            Some((address, label))
        })
    else {
        return ctx.identify_again(
            StatusCode::UNPROCESSABLE_ENTITY,
            Message::InvalidAddress,
            '0',
            "",
        );
    };
    let retry = |status, message| {
        ctx.sign_in_step(pub_dress.as_str(), pub_dress.slug(), Some(message), status)
    };
    let source_key = format!("auth:source:{}", ctx.source);
    // Keyed by the canonical label, so case variants of one address share
    // one lock.
    let address_key = format!("auth:address:{label}");
    if !ctx.state.limiter.allow(&source_key, ctx.now, 20, 15 * 60)
        || !ctx.state.limiter.allow(&address_key, ctx.now, 10, 15 * 60)
        || !ctx.state.limiter.allow("auth:global", ctx.now, 2_000, 60)
    {
        return retry(StatusCode::TOO_MANY_REQUESTS, Message::RateLimited);
    }
    let identity = match ctx.state.store.find(&pub_dress).await {
        Ok(value) => value,
        Err(_) => {
            return page::error_page(
                ctx.language,
                StatusCode::SERVICE_UNAVAILABLE,
                Message::Unavailable,
            );
        }
    };
    // The same Argon2 work whether or not the address exists.
    let hash = identity.as_ref().map_or_else(
        || ctx.state.dummy_hash.to_string(),
        |identity| identity.password_hash.clone(),
    );
    let password = form.password.clone();
    let engine = ctx.state.passwords.clone();
    let matches = tokio::task::spawn_blocking(move || engine.verify(&password, &hash))
        .await
        .unwrap_or(false);
    let Some(identity) = identity.filter(|_| matches) else {
        return retry(StatusCode::UNAUTHORIZED, Message::InvalidCredentials);
    };
    ctx.state.limiter.clear(&address_key);
    complete(ctx, &identity).await
}

async fn register(ctx: &Ctx<'_>, form: &SubmitForm) -> Response {
    let Some(assigned) = ctx
        .state
        .keys
        .open::<Assignment>(ASSIGNMENT_DOMAIN, &form.assignment)
        .filter(|assignment| {
            bool::from(
                assignment
                    .browser
                    .as_bytes()
                    .ct_eq(ctx.request.browser.as_bytes()),
            )
        })
        .and_then(|assignment| PubDress::from_str(&assignment.pub_dress).ok())
    else {
        return page::error_page(ctx.language, StatusCode::BAD_REQUEST, Message::Expired);
    };
    let retry = |status, message| ctx.register_step(&assigned, Some(message), status);
    if !ctx
        .state
        .limiter
        .allow(&format!("register:{}", ctx.source), ctx.now, 8, 60 * 60)
        || !ctx
            .state
            .limiter
            .allow("register:global", ctx.now, 500, 60 * 60)
    {
        return retry(StatusCode::TOO_MANY_REQUESTS, Message::RateLimited);
    }
    if form.password != form.password_confirm {
        return retry(StatusCode::UNPROCESSABLE_ENTITY, Message::PasswordsDiffer);
    }
    let normalized = match ctx.state.passwords.validate(&form.password) {
        Ok(value) => value,
        Err(PolicyError::Length) => {
            return retry(StatusCode::UNPROCESSABLE_ENTITY, Message::PasswordLength);
        }
        Err(PolicyError::Whitespace) => {
            return retry(
                StatusCode::UNPROCESSABLE_ENTITY,
                Message::PasswordWhitespace,
            );
        }
    };
    let engine = ctx.state.passwords.clone();
    let Ok(Some(hash)) = tokio::task::spawn_blocking(move || engine.hash(&normalized)).await else {
        return page::error_page(
            ctx.language,
            StatusCode::SERVICE_UNAVAILABLE,
            Message::Unavailable,
        );
    };
    let prefix_assigned = ctx.client.skin == Skin::Slug;
    match ctx
        .state
        .store
        .register(&assigned, prefix_assigned, &hash, ctx.now)
        .await
    {
        Ok(Registration::Registered(identity)) => complete(ctx, &identity).await,
        Ok(Registration::Unrepresentable) => ctx.identify_again(
            StatusCode::UNPROCESSABLE_ENTITY,
            Message::InvalidAddress,
            '0',
            assigned.slug(),
        ),
        Ok(Registration::Taken) => ctx.identify_again(
            StatusCode::CONFLICT,
            Message::Taken,
            match ctx.client.skin {
                Skin::Cell => assigned.discriminator(),
                Skin::Slug => '0',
            },
            assigned.slug(),
        ),
        Err(_) => page::error_page(
            ctx.language,
            StatusCode::SERVICE_UNAVAILABLE,
            Message::Unavailable,
        ),
    }
}

fn code_key(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}

/// The person is authenticated: hand the client a single-use code.
async fn complete(ctx: &Ctx<'_>, identity: &Identity) -> Response {
    let request = &ctx.request;
    let subject = ctx
        .state
        .keys
        .pairwise_subject(&request.client_id, &identity.subject);
    let Some(code) = random_token(32) else {
        return redirect_error(&request.redirect_uri, "server_error", &request.state);
    };
    {
        let mut codes = ctx.state.codes.lock().expect("code store lock poisoned");
        codes.retain(|_, pending| pending.expires_at > ctx.now);
        if codes.len() >= MAX_PENDING_CODES {
            return redirect_error(
                &request.redirect_uri,
                "temporarily_unavailable",
                &request.state,
            );
        }
        codes.insert(
            code_key(&code),
            PendingCode {
                client_id: request.client_id.clone(),
                redirect_uri: request.redirect_uri.clone(),
                code_challenge: request.code_challenge.clone(),
                nonce: request.nonce.clone(),
                subject,
                pub_dress: request.pub_dress_scope.then(|| identity.pub_dress.clone()),
                auth_time: ctx.now,
                expires_at: ctx.now + CODE_TTL,
            },
        );
    }
    let Ok(mut location) = Url::parse(&request.redirect_uri) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request.state);
    let mut response = redirect(location.as_str());
    append_cookie(
        &mut response,
        &format!("{BROWSER_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"),
    );
    let hint = ctx.state.keys.seal(
        HINT_DOMAIN,
        &Hint {
            pub_dress: identity.pub_dress.clone(),
            expires_at: ctx.now + HINT_TTL,
        },
    );
    append_cookie(&mut response, &cookie(HINT_COOKIE, &hint, HINT_TTL));
    response
}

// ---------------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let now = now();
    let Some(client) = authenticate_client(&state, &headers, &form) else {
        let mut response = token_error(StatusCode::UNAUTHORIZED, "invalid_client");
        response.headers_mut().insert(
            "www-authenticate",
            HeaderValue::from_static("Basic realm=\"aiaiaiai\""),
        );
        return response;
    };
    if form.grant_type.as_deref() != Some("authorization_code") {
        return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let (Some(code), Some(redirect_uri), Some(verifier)) = (
        form.code.as_deref(),
        form.redirect_uri.as_deref(),
        form.code_verifier.as_deref(),
    ) else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    // Taken out before any check: a code is spent by its first exchange,
    // right or wrong.
    let pending = state
        .codes
        .lock()
        .expect("code store lock poisoned")
        .remove(&code_key(code));
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'));
    let Some(pending) = pending.filter(|pending| {
        pending.expires_at > now
            && pending.client_id == client.client_id
            && pending.redirect_uri == redirect_uri
            && verifier_ok
            && bool::from(
                URL_SAFE_NO_PAD
                    .encode(Sha256::digest(verifier.as_bytes()))
                    .as_bytes()
                    .ct_eq(pending.code_challenge.as_bytes()),
            )
    }) else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let mut claims = serde_json::json!({
        "iss": state.config.issuer_id(),
        "sub": pending.subject,
        "aud": client.client_id,
        "exp": now + ID_TOKEN_TTL,
        "iat": now,
        "auth_time": pending.auth_time,
        "nonce": pending.nonce,
        "amr": ["pwd"],
    });
    if let Some(pub_dress) = pending.pub_dress {
        claims["pub_dress"] = serde_json::Value::String(pub_dress);
    }
    let id_token = sign_jwt(&state.config.signing_key, &state.config.key_id, &claims);
    // OIDC requires an access token in the response. No resource accepts it
    // yet: there is no userinfo endpoint.
    let Some(access_token) = random_token(32) else {
        return token_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    no_store(
        StatusCode::OK,
        serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ID_TOKEN_TTL,
            "id_token": id_token,
        }),
    )
}

fn authenticate_client(state: &AppState, headers: &HeaderMap, form: &TokenForm) -> Option<Client> {
    let basic = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| STANDARD.decode(encoded.trim()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|pair| {
            let (id, secret) = pair.split_once(':')?;
            Some((form_decode(id), form_decode(secret)))
        });
    let (client_id, secret) = match (basic, &form.client_id, &form.client_secret) {
        (Some((id, secret)), None, None) => (id, Some(secret)),
        (None, Some(id), Some(secret)) => (id.clone(), Some(secret.clone())),
        // A public client names itself and sends no secret.
        (None, Some(id), None) => (id.clone(), None),
        _ => return None,
    };
    let client = state.config.clients.get(&client_id)?;
    match (client.secret_sha256, secret) {
        (Some(expected), Some(secret)) => {
            let supplied: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
            bool::from(supplied.ct_eq(&expected)).then(|| client.clone())
        }
        (None, None) => Some(client.clone()),
        // A public client that presents a secret, or a confidential one that
        // presents none, is misconfigured or an impostor; neither is let in.
        _ => None,
    }
}

/// RFC 6749 §2.3.1: Basic credentials are form-encoded first.
fn form_decode(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_default()
}

fn token_error(status: StatusCode, error: &'static str) -> Response {
    no_store(status, serde_json::json!({ "error": error }))
}

fn no_store(status: StatusCode, value: serde_json::Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
    response
}
