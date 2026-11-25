// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! End-to-end: the page, both skins, the token endpoint, and the 0x1 client's
//! own verifier (`nilx-one/core` `aiaiaiai_sign_in`) accepting what AIS issues.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nilxone_identity::aiaiaiai_sign_in::{
    Expectation, JsonWebKeySet, SignInError, VerifiedSignIn, code_challenge, verify_id_token,
};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use url::Url;

use crate::{config::Config, router, store::Store};

const ISSUER: &str = "https://auth.aiaiaiai.org";
const HOST_NAME: &str = "auth.aiaiaiai.org";
const ONE_CALLBACK: &str = "https://nilx.one/api/v1/auth/aiaiaiai/callback";
/// The 0x1 host's Telegram login callback: nilx-one/core `CALLBACK_PATH` in
/// crates/nilxone-identity/src/public_info/telegram_login.rs.
pub(crate) const TELEGRAM_CALLBACK: &str = "https://nilx.one/api/v1/telegram/login/callback";
const PRISM_CALLBACK: &str = "https://prism.aiaiaiai.org/auth/callback";
const OPEN_CALLBACK: &str = "https://open.example/auth/callback";
const SECRET: &str = "a-client-secret-of-thirty-two-bytes!";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "a-pkce-verifier-that-is-long-enough-for-rfc-7636";

const MARKET_KEY: [u8; 32] = [11; 32];
const HUB_KEY: [u8; 32] = [12; 32];
const ONE_KEY: [u8; 32] = [13; 32];

fn public_key(seed: [u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes(),
    )
}

fn hex_sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn app() -> Router {
    let store = Store::connect("sqlite::memory:").await.expect("store");
    app_with_store(store)
}

fn app_with_store(store: Store) -> Router {
    let clients = serde_json::json!([
        { "client_id": "nilx-one", "name": "0x1", "skin": "cell", "redirect_uris": [ONE_CALLBACK],
          "secret_sha256": hex_sha256(SECRET), "pub_dress": true,
          "product": { "keys": [{ "kid": "o1", "x": public_key(ONE_KEY) }] } },
        // 0x1 as in production, plus test-only product grants.
        { "client_id": "0x1", "name": "0x1", "skin": "cell", "redirect_uris": [ONE_CALLBACK, TELEGRAM_CALLBACK],
          "pub_dress": true, "telegram_binding_redirect_uri": TELEGRAM_CALLBACK,
          "product": { "keys": [{ "kid": "o1", "x": public_key(ONE_KEY) }],
                       "tokens": { "prism-hub": ["telegram.link.put", "bond.profile.read", "bond.profile.write"], "ais": ["telegram.identity.resolve"] } } },
        { "client_id": "prism", "name": "Prism", "skin": "slug", "redirect_uris": [PRISM_CALLBACK],
          "secret_sha256": hex_sha256(SECRET) },
        // A public client: no secret, only PKCE.
        { "client_id": "open-app", "name": "Open", "skin": "slug", "redirect_uris": [OPEN_CALLBACK] },
        // Family products (hub.v1): keys and token grants, no secret.
        { "client_id": "0xda-market", "name": "0xda-market", "skin": "cell", "redirect_uris": [],
          "product": { "keys": [{ "kid": "m1", "x": public_key(MARKET_KEY) }],
                       "tokens": { "prism-hub": ["hub.call", "hub.events", "telegram.special.purchase", "bond.profile.read"] } } },
        // Holds the link scope but is not 0x1: tests the actor check.
        { "client_id": "partner", "name": "Partner", "skin": "cell", "redirect_uris": [],
          "product": { "keys": [{ "kid": "p1", "x": public_key(MARKET_KEY) }],
                       "tokens": { "prism-hub": ["telegram.link.put"] } } },
        { "client_id": "prism-hub", "name": "Prism Hub", "skin": "slug", "redirect_uris": [],
          "product": { "keys": [{ "kid": "h1", "x": public_key(HUB_KEY) }],
                       "tokens": { "0xda-market": ["hub.relay"], "ais": ["pass.issue", "accounts.put", "link.read", "telegram.link.put", "telegram.special.purchase", "bond.profile.read", "bond.profile.write"] }, "relay": true } },
    ])
    .to_string();
    let config = Config::from_lookup(move |key| {
        Some(match key {
            "AIS_ISSUER" => ISSUER.to_owned(),
            "AIS_SIGNING_KEY" => {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3_u8; 32])
            }
            "AIS_SECRET" => "a-test-secret-that-is-at-least-32-bytes".to_owned(),
            "AIS_PASSWORD_PEPPER" => "a-test-pepper-that-is-at-least-32-bytes".to_owned(),
            "AIS_CLIENTS" => clients.clone(),
            _ => return None,
        })
    })
    .expect("test configuration");
    router(config, store)
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8_lossy(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
        .into_owned();
    Reply {
        status,
        headers,
        body,
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, HOST_NAME)
        .body(Body::empty())
        .unwrap()
}

fn post_form(uri: &str, cookie: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    Request::post(uri)
        .header(header::HOST, HOST_NAME)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap()
}

fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("field {name} in {html}"))
        + marker.len();
    html[start..]
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&")
}

fn set_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
}

fn location(headers: &HeaderMap) -> Url {
    Url::parse(
        headers
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .unwrap(),
    )
    .unwrap()
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// One authorization request from a client, with the page it opens.
struct Flow {
    client_id: &'static str,
    callback: &'static str,
    nonce: String,
    request: String,
    cookie: String,
    page: String,
}

async fn open(
    app: &Router,
    client_id: &'static str,
    callback: &'static str,
    hint: Option<&str>,
) -> Flow {
    let nonce = format!("nonce-{client_id}");
    let scope = if client_id == "nilx-one" || client_id == "0x1" {
        "openid pub_dress"
    } else {
        "openid"
    };
    let mut url = Url::parse(&format!("{ISSUER}/authorize")).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", callback)
        .append_pair("scope", scope)
        .append_pair("state", "the-state")
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge(VERIFIER))
        .append_pair("code_challenge_method", "S256");
    let mut request = get(&format!("/authorize?{}", url.query().unwrap()));
    if let Some(hint) = hint {
        request
            .headers_mut()
            .insert(header::COOKIE, hint.parse().unwrap());
    }
    let reply = send(app, request).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    Flow {
        client_id,
        callback,
        nonce,
        request: hidden(&reply.body, "request"),
        cookie: set_cookie(&reply.headers, "__Host-ais_authz").expect("browser cookie"),
        page: reply.body,
    }
}

impl Flow {
    async fn post(&self, app: &Router, fields: &[(&str, &str)]) -> Reply {
        let mut all = vec![("request", self.request.as_str())];
        all.extend_from_slice(fields);
        send(app, post_form("/authorize", &self.cookie, &all)).await
    }

    async fn exchange(&self, app: &Router, code: &str) -> Reply {
        self.exchange_with_binding(app, code, None).await
    }

    async fn exchange_with_binding(
        &self,
        app: &Router,
        code: &str,
        binding_hint: Option<&str>,
    ) -> Reply {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.callback),
            ("code_verifier", VERIFIER),
        ];
        if let Some(hint) = binding_hint {
            pairs.push(("telegram_binding_hint", hint));
        }
        let mut request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if self.client_id == "open-app" || self.client_id == "0x1" {
            // A public client names itself and sends no secret.
            pairs.push(("client_id", self.client_id));
        } else {
            request = request.header(
                header::AUTHORIZATION,
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{SECRET}", self.client_id))
                ),
            );
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        send(app, request.body(Body::from(body)).unwrap()).await
    }

    /// Exchanges the code and verifies the token with the 0x1 client's code.
    async fn verified(
        &self,
        app: &Router,
        redirect: &Reply,
    ) -> Result<VerifiedSignIn, SignInError> {
        assert_eq!(redirect.status, StatusCode::SEE_OTHER, "{}", redirect.body);
        let back = location(&redirect.headers);
        assert_eq!(query(&back, "state").as_deref(), Some("the-state"));
        let reply = self
            .exchange(app, &query(&back, "code").expect("code"))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let token: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        let keys: JsonWebKeySet =
            serde_json::from_str(&send(app, get("/.well-known/jwks.json")).await.body).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verify_id_token(
            token["id_token"].as_str().unwrap(),
            &keys,
            &Expectation {
                issuer: ISSUER,
                client_id: self.client_id,
                nonce: &self.nonce,
            },
            now,
        )
    }
}

/// Registers through the 0x1 (`cell`) page with a chosen prefix.
async fn register_cell(app: &Router, prefix: &str, slug: &str) -> (Flow, Reply) {
    register_cell_for(app, "nilx-one", prefix, slug).await
}

async fn register_cell_for(
    app: &Router,
    client: &'static str,
    prefix: &str,
    slug: &str,
) -> (Flow, Reply) {
    let flow = open(app, client, ONE_CALLBACK, None).await;
    let page = flow
        .post(
            app,
            &[("step", "identify"), ("prefix", prefix), ("slug", slug)],
        )
        .await;
    assert!(
        page.body.contains("autocomplete=\"new-password\""),
        "{}",
        page.body
    );
    let assignment = hidden(&page.body, "assignment");
    let reply = flow
        .post(
            app,
            &[
                ("step", "register"),
                ("assignment", &assignment),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
        )
        .await;
    (flow, reply)
}

#[tokio::test]
async fn product_scoped_0x1_entry_keeps_oidc_verification_and_subject_isolation() {
    let app = app().await;
    let mut url = Url::parse(&format!("{ISSUER}/0x1")).unwrap();
    let nonce = "nonce-0x1".to_owned();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", ONE_CALLBACK)
        .append_pair("scope", "openid pub_dress")
        .append_pair("state", "the-state")
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge(VERIFIER))
        .append_pair("code_challenge_method", "S256");
    // Entry is pinned to 0x1 without allowing the caller to override the client.
    let reply = send(&app, get(&format!("/0x1?{}", url.query().unwrap()))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("aiaiaiai AIS × <span class=\"auth-product-name\">0x1</span>")
    );
    let flow = Flow {
        client_id: "0x1",
        callback: ONE_CALLBACK,
        nonce,
        request: hidden(&reply.body, "request"),
        cookie: set_cookie(&reply.headers, "__Host-ais_authz").unwrap(),
        page: reply.body,
    };
    let page = flow
        .post(
            &app,
            &[("step", "identify"), ("prefix", "0"), ("slug", "scoped")],
        )
        .await;
    let assignment = hidden(&page.body, "assignment");
    let finished = flow
        .post(
            &app,
            &[
                ("step", "register"),
                ("assignment", &assignment),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
        )
        .await;
    let successor = flow
        .verified(&app, &finished)
        .await
        .expect("0x1 audience verified");
    assert_eq!(successor.pub_dress.as_deref(), Some("0x0scoped"));

    // The pre-existing client keeps a distinct pairwise subject.
    let legacy = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let login = legacy
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0scoped"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let predecessor = legacy
        .verified(&app, &login)
        .await
        .expect("legacy audience verified");
    assert_ne!(successor.subject, predecessor.subject);
}

#[tokio::test]
async fn direct_0x1_entry_is_visible_but_never_starts_authentication() {
    let app = app().await;
    let reply = send(&app, get("/0x1")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Sign in to 0x1"), "{}", reply.body);
    assert!(
        reply
            .body
            .contains("https://nilx.one/api/v1/auth/aiaiaiai/start?return=%2F")
    );
    assert!(reply.headers.get(header::LOCATION).is_none());
    assert!(set_cookie(&reply.headers, "__Host-ais_authz").is_none());
    assert!(!reply.body.contains("name=\"request\""));
    assert_eq!(
        reply.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let ukrainian = send(
        &app,
        Request::get("/0x1")
            .header(header::HOST, HOST_NAME)
            .header(header::ACCEPT_LANGUAGE, "uk-UA")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(ukrainian.status, StatusCode::OK);
    assert!(ukrainian.body.contains("Вхід до 0x1"));
    assert!(ukrainian.headers.get(header::LOCATION).is_none());
    assert!(set_cookie(&ukrainian.headers, "__Host-ais_authz").is_none());
}

/// The 0x1 world is presentation for the 0x1 clients only. It adds no
/// script, no style attribute and no field: other products keep the neutral
/// page, and the CSP stays as strict as before.
#[tokio::test]
async fn only_the_0x1_clients_open_in_the_0x1_world() {
    let app = app().await;
    for (client_id, callback) in [("nilx-one", ONE_CALLBACK), ("0x1", ONE_CALLBACK)] {
        let flow = open(&app, client_id, callback, None).await;
        assert!(
            flow.page.contains("<body class=\"world-0x1\">"),
            "{}",
            flow.page
        );
        assert!(flow.page.contains("Sign in to 0x1"), "{}", flow.page);
        assert!(
            flow.page.contains(&format!("{HOST_NAME}/0x1")),
            "{}",
            flow.page
        );
        assert!(!flow.page.contains("<script"));
        assert!(!flow.page.contains(" style="));
    }
    for (client_id, callback) in [("prism", PRISM_CALLBACK), ("open-app", OPEN_CALLBACK)] {
        let flow = open(&app, client_id, callback, None).await;
        assert!(flow.page.contains("<body><main"), "{}", flow.page);
        assert!(!flow.page.contains("world-"), "{}", flow.page);
    }

    let entry = send(&app, get("/0x1")).await;
    assert!(entry.body.contains("<body class=\"world-0x1\">"));
    assert!(!entry.body.contains("<script"));
    assert!(!entry.body.contains(" style="));
    let csp = entry.headers.get("content-security-policy").unwrap();
    assert!(
        csp.to_str()
            .unwrap()
            .starts_with("default-src 'none'; style-src 'self';")
    );
}

#[tokio::test]
async fn product_scoped_entry_fails_closed_without_a_valid_client_request() {
    let app = app().await;
    for uri in [
        "/0x1?client_id=0x1",
        "/0x1?client_id=prism",
        "/0x1?client_id=nilx-one",
        "/0x1?redirect_uri=https://attacker.example/cb",
    ] {
        let reply = send(&app, get(uri)).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{uri}: {}",
            reply.body
        );
        assert!(reply.headers.get(header::LOCATION).is_none(), "{uri}");
        assert!(
            set_cookie(&reply.headers, "__Host-ais_authz").is_none(),
            "{uri}"
        );
    }
    let reply = send(
        &app,
        Request::get("/0x1")
            .header(header::HOST, "attacker.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_cell_registration_reaches_the_0x1_client_as_a_verified_sign_in() {
    let app = app().await;
    let (flow, reply) = register_cell(&app, "f", "reezbylove").await;
    let verified = flow
        .verified(&app, &reply)
        .await
        .expect("Core accepts the token");
    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.pub_dress.as_deref(), Some("0xfreezbylove"));
    let hint = set_cookie(&reply.headers, "__Host-ais_hint").expect("hint");

    // Signing in again: the hint prefills the address, the same subject returns.
    let again = open(&app, "nilx-one", ONE_CALLBACK, Some(&hint)).await;
    assert!(
        again.page.contains("value=\"reezbylove\""),
        "{}",
        again.page
    );
    assert!(
        again.page.contains("value=\"f\" selected"),
        "{}",
        again.page
    );
    let page = again
        .post(
            &app,
            &[
                ("step", "identify"),
                ("prefix", "f"),
                ("slug", "reezbylove"),
            ],
        )
        .await;
    assert!(
        page.body.contains("autocomplete=\"current-password\""),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("id=\"username\" name=\"pub_dress\" type=\"text\""),
        "the cell sign-in address must be a real editable username"
    );
    assert!(page.body.contains("src=\"/static/credential-autofill.js\""));
    assert!(
        page.body
            .contains("<html lang=\"en\" class=\"world-0x1-root\"")
    );
    assert!(
        page.body
            .contains("name=\"theme-color\" content=\"#3d4778\"")
    );
    assert!(page.body.contains("viewport-fit=cover"));
    let csp = page
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self';"));
    let script = send(&app, get("/static/credential-autofill.js")).await;
    assert_eq!(script.status, StatusCode::OK);
    assert_eq!(
        script.headers.get(header::CONTENT_TYPE).unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert!(script.body.contains("form.requestSubmit(button)"));
    let signed_in = again
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0xfreezbylove"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let second = again.verified(&app, &signed_in).await.expect("verified");
    assert_eq!(second.subject, verified.subject);
}

#[tokio::test]
async fn the_cell_page_offers_the_whole_prefix_as_one_choice() {
    let app = app().await;
    let flow = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    for prefix in ["0x0", "0x7", "0xf"] {
        assert!(
            flow.page.contains(&format!(">{prefix}</option>")),
            "{prefix}"
        );
    }
    assert!(
        !flow.page.contains("class=\"address-prefix\""),
        "no separate fixed 0x"
    );
    assert!(
        flow.page
            .contains("aiaiaiai AIS × <span class=\"auth-product-name\">0x1</span>")
    );
}

#[tokio::test]
async fn the_slug_page_never_shows_the_prefix_and_ais_assigns_it() {
    let app = app().await;
    let flow = open(&app, "prism", PRISM_CALLBACK, None).await;
    assert!(!flow.page.contains("<select"), "{}", flow.page);
    assert!(
        flow.page
            .contains("aiaiaiai AIS × <span class=\"auth-product-name\">Prism</span>")
    );
    let page = flow
        .post(&app, &[("step", "identify"), ("slug", "analyst")])
        .await;
    assert!(!page.body.contains("<select"));
    let assigned = hidden(&page.body, "pub_dress");
    assert!(
        assigned.starts_with("0x") && assigned.ends_with("analyst"),
        "{assigned}"
    );
    // The full address is the password manager's account name, out of sight.
    assert!(page.body.contains(&format!(
        "class=\"visually-hidden\" tabindex=\"-1\" aria-hidden=\"true\" value=\"{assigned}\""
    )));
    let assignment = hidden(&page.body, "assignment");
    let reply = flow
        .post(
            &app,
            &[
                ("step", "register"),
                ("assignment", &assignment),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
        )
        .await;
    let verified = flow.verified(&app, &reply).await.expect("verified");
    assert_eq!(
        verified.pub_dress, None,
        "Prism does not ask for the address"
    );
}

/// Only the `cell` sign-in lets a password manager choose another saved
/// address; registration stays bound to the assigned one, the `slug` skin
/// keeps its hidden address, and only sign-in pages run any script.
#[tokio::test]
async fn only_the_cell_sign_in_accepts_a_different_saved_address() {
    let app = app().await;
    let csp = |reply: &Reply| {
        reply
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };
    let hidden_address = "<input type=\"hidden\" name=\"pub_dress\"";

    // Registration: bound to the server-assigned address, no script at all.
    let flow = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let register = flow
        .post(
            &app,
            &[("step", "identify"), ("prefix", "0"), ("slug", "analyst")],
        )
        .await;
    assert!(register.body.contains("autocomplete=\"new-password\""));
    assert!(register.body.contains(hidden_address), "{}", register.body);
    assert!(register.body.contains("autocomplete=\"username\" readonly"));
    assert!(!register.body.contains("<script"), "{}", register.body);
    assert!(!csp(&register).contains("script-src"), "{}", csp(&register));
    register_cell(&app, "0", "analyst").await;

    // `cell` sign-in: the address itself is the editable username.
    let cell = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let cell = cell
        .post(
            &app,
            &[("step", "identify"), ("prefix", "0"), ("slug", "analyst")],
        )
        .await;
    assert!(cell.body.contains("autocomplete=\"current-password\""));
    assert!(!cell.body.contains(hidden_address), "{}", cell.body);
    assert!(csp(&cell).contains("script-src 'self';"));

    // `slug` sign-in: the hidden address decides; the username only files it.
    let slug = open(&app, "prism", PRISM_CALLBACK, None).await;
    let slug = slug
        .post(&app, &[("step", "identify"), ("slug", "analyst")])
        .await;
    assert!(slug.body.contains("autocomplete=\"current-password\""));
    assert_eq!(hidden(&slug.body, "pub_dress"), "0x0analyst");
    assert!(
        !slug.body.contains("autocomplete=\"username\" readonly"),
        "{}",
        slug.body
    );
    assert!(slug.body.contains("src=\"/static/credential-autofill.js\""));
    assert!(!slug.body.contains("world-0x1-root"), "{}", slug.body);

    // Pages without a form stay script-free.
    let landing = send(&app, get("/")).await;
    assert!(!landing.body.contains("<script"));
    assert!(!csp(&landing).contains("script-src"));
}

#[tokio::test]
async fn a_shared_slug_asks_which_address_is_yours() {
    let app = app().await;
    register_cell(&app, "0", "sky").await;
    register_cell(&app, "1", "sky").await;
    let flow = open(&app, "prism", PRISM_CALLBACK, None).await;
    let page = flow
        .post(&app, &[("step", "identify"), ("slug", "sky")])
        .await;
    assert!(
        page.body.contains(">0x0</option>") && page.body.contains(">0x1</option>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains(">0x2</option>"));
    let chosen = flow
        .post(
            &app,
            &[("step", "choose"), ("prefix", "1"), ("slug", "sky")],
        )
        .await;
    assert!(chosen.body.contains("value=\"0x1sky\""), "{}", chosen.body);
}

#[tokio::test]
async fn a_returning_person_is_found_however_they_type_the_case() {
    let app = app().await;
    register_cell(&app, "0", "Sky").await;

    // 0x1 (`cell`): the lowercase spelling signs in, it does not report "taken".
    let flow = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let page = flow
        .post(
            &app,
            &[("step", "identify"), ("prefix", "0"), ("slug", "sky")],
        )
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("autocomplete=\"current-password\"")
            && page.body.contains("value=\"0x0Sky\""),
        "{}",
        page.body
    );

    // Prism (`slug`): the person is not routed into a second account.
    let flow = open(&app, "prism", PRISM_CALLBACK, None).await;
    let page = flow
        .post(&app, &[("step", "identify"), ("slug", "SKY")])
        .await;
    assert!(
        page.body.contains("autocomplete=\"current-password\"")
            && page.body.contains("value=\"0x0Sky\""),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn an_address_without_a_public_label_is_invalid_not_taken() {
    use std::str::FromStr as _;
    // The case under test: the grammar accepts it, the label does not.
    let edge = nilxone_contracts::PubDress::from_str("0x0sky-").expect("grammar accepts");
    assert!(nilxone_contracts::PubDressLabel::stem(&edge).is_err());

    let app = app().await;
    let cell = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let page = cell
        .post(
            &app,
            &[("step", "identify"), ("prefix", "0"), ("slug", "sky-")],
        )
        .await;
    assert_eq!(
        page.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        page.body
    );
    let slug = open(&app, "prism", PRISM_CALLBACK, None).await;
    let page = slug
        .post(&app, &[("step", "identify"), ("slug", "sky-")])
        .await;
    assert_eq!(
        page.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_client_cannot_choose_its_own_limit_key() {
    let app = app().await;
    let flow = open(&app, "prism", PRISM_CALLBACK, None).await;
    let mut last = StatusCode::OK;
    for attempt in 0..61 {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("request", flow.request.as_str()),
                ("step", "identify"),
                ("slug", "nobody"),
            ])
            .finish();
        // The client invents a new first hop each time; the edge appends the
        // address it actually saw.
        let request = Request::post("/authorize")
            .header(header::HOST, HOST_NAME)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &flow.cookie)
            .header("x-forwarded-for", format!("10.0.0.{attempt}, 203.0.113.7"))
            .body(Body::from(body))
            .unwrap();
        last = send(&app, request).await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_0x1_token_on_the_telegram_callback_has_its_own_subject_and_no_alias() {
    let app = app().await;
    let (legacy, created) = register_cell(&app, "0", "continuity").await;
    let old = legacy.verified(&app, &created).await.unwrap();
    let successor = open(&app, "0x1", TELEGRAM_CALLBACK, None).await;
    let signed_in = successor
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0continuity"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let back = location(&signed_in.headers);
    let response = successor
        .exchange(&app, &query(&back, "code").unwrap())
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let token: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    let jwt = token["id_token"].as_str().unwrap();
    let payload = jwt.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    let mut redirect = back;
    redirect.set_query(None);
    assert_eq!(redirect.as_str(), TELEGRAM_CALLBACK);
    assert_eq!(claims["aud"], "0x1");
    assert_ne!(claims["sub"], old.subject);
    assert!(claims.get("subject_continuity").is_none());
    let keys: JsonWebKeySet =
        serde_json::from_str(&send(&app, get("/.well-known/jwks.json")).await.body).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let verified = verify_id_token(
        jwt,
        &keys,
        &Expectation {
            issuer: ISSUER,
            client_id: "0x1",
            nonce: &successor.nonce,
        },
        now,
    )
    .unwrap();
    assert_eq!(verified.subject, claims["sub"].as_str().unwrap());
    assert_eq!(
        verify_id_token(
            jwt,
            &keys,
            &Expectation {
                issuer: ISSUER,
                client_id: "nilx-one",
                nonce: &successor.nonce
            },
            now,
        ),
        Err(SignInError::InvalidToken("audience"))
    );

    // A second sign-in is stable; a token for another client does not disclose
    // the old 0x1 subject, even when the person uses the same password.
    let again = open(&app, "0x1", ONE_CALLBACK, None).await;
    let retry = again
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0continuity"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(
        again.verified(&app, &retry).await.unwrap().subject,
        verified.subject
    );
    let prism = open(&app, "prism", PRISM_CALLBACK, None).await;
    let prism_redirect = prism
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0continuity"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let exchange = prism
        .exchange(
            &app,
            &query(&location(&prism_redirect.headers), "code").unwrap(),
        )
        .await;
    let prism_token: serde_json::Value = serde_json::from_str(&exchange.body).unwrap();
    let prism_claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                prism_token["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(prism_claims.get("subject_continuity").is_none());
    assert_ne!(prism_claims["sub"], claims["sub"]);
}

#[tokio::test]
async fn one_person_is_a_different_sub_for_each_product() {
    let app = app().await;
    let (one, reply) = register_cell(&app, "0", "sky").await;
    let for_one = one.verified(&app, &reply).await.unwrap();
    let prism = open(&app, "prism", PRISM_CALLBACK, None).await;
    prism
        .post(&app, &[("step", "identify"), ("slug", "sky")])
        .await;
    let signed_in = prism
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0sky"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let for_prism = prism.verified(&app, &signed_in).await.unwrap();
    assert_ne!(for_one.subject, for_prism.subject);
}

#[tokio::test]
async fn a_tampered_assignment_cannot_choose_the_prefix() {
    let app = app().await;
    let flow = open(&app, "prism", PRISM_CALLBACK, None).await;
    flow.post(&app, &[("step", "identify"), ("slug", "analyst")])
        .await;
    let reply = flow
        .post(
            &app,
            &[
                ("step", "register"),
                ("assignment", "v1.forged.mac"),
                ("pub_dress", "0x7analyst"),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.headers.get(header::LOCATION).is_none());
}

#[tokio::test]
async fn a_wrong_password_or_mismatched_confirmation_issues_no_code() {
    let app = app().await;
    register_cell(&app, "0", "sky").await;
    let flow = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let reply = flow
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0sky"),
                ("password", "not the password"),
            ],
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.headers.get(header::LOCATION).is_none());

    let fresh = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let page = fresh
        .post(
            &app,
            &[("step", "identify"), ("prefix", "2"), ("slug", "sea")],
        )
        .await;
    let assignment = hidden(&page.body, "assignment");
    let mismatch = fresh
        .post(
            &app,
            &[
                ("step", "register"),
                ("assignment", &assignment),
                ("password", PASSWORD),
                ("password_confirm", "different words"),
            ],
        )
        .await;
    assert_eq!(mismatch.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_unknown_client_or_redirect_never_redirects() {
    let app = app().await;
    for query in [
        format!("client_id=evil&redirect_uri={ONE_CALLBACK}"),
        "client_id=nilx-one&redirect_uri=https://evil.example/cb".to_owned(),
    ] {
        let reply = send(&app, get(&format!("/authorize?{query}"))).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert!(reply.headers.get(header::LOCATION).is_none(), "{query}");
    }
}

#[tokio::test]
async fn a_request_without_pkce_goes_back_with_an_error() {
    let app = app().await;
    let uri = format!(
        "/authorize?response_type=code&client_id=nilx-one&redirect_uri={}&scope=openid&state=s&nonce=n",
        url::form_urlencoded::byte_serialize(ONE_CALLBACK.as_bytes()).collect::<String>()
    );
    let reply = send(&app, get(&uri)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let back = location(&reply.headers);
    assert_eq!(query(&back, "error").as_deref(), Some("invalid_request"));
    assert_eq!(query(&back, "state").as_deref(), Some("s"));
}

#[tokio::test]
async fn the_page_answers_only_on_the_issuer_host_and_its_own_browser() {
    let app = app().await;
    let request = Request::get("/authorize?client_id=nilx-one")
        .header(header::HOST, "nilx.one")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, request).await.status, StatusCode::NOT_FOUND);
    let flow = open(&app, "nilx-one", ONE_CALLBACK, None).await;
    let reply = send(
        &app,
        post_form(
            "/authorize",
            "__Host-ais_authz=someone-else",
            &[
                ("request", &flow.request),
                ("step", "identify"),
                ("prefix", "0"),
                ("slug", "sky"),
            ],
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_token_endpoint_spends_a_code_on_its_first_exchange() {
    let app = app().await;
    let (flow, reply) = register_cell(&app, "0", "sky").await;
    let code = query(&location(&reply.headers), "code").unwrap();
    let wrong_secret = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {}", STANDARD.encode("nilx-one:wrong")))
        .body(Body::from(format!("grant_type=authorization_code&code={code}&redirect_uri={ONE_CALLBACK}&code_verifier={VERIFIER}")))
        .unwrap();
    assert_eq!(
        send(&app, wrong_secret).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(flow.exchange(&app, &code).await.status, StatusCode::OK);
    let reused = flow.exchange(&app, &code).await;
    assert_eq!(reused.status, StatusCode::BAD_REQUEST);
    assert!(reused.body.contains("invalid_grant"));
}

#[tokio::test]
async fn a_public_client_proves_its_code_with_pkce_and_no_secret() {
    let app = app().await;
    let flow = open(&app, "open-app", OPEN_CALLBACK, None).await;
    let page = flow
        .post(&app, &[("step", "identify"), ("slug", "wanderer")])
        .await;
    let assignment = hidden(&page.body, "assignment");
    let reply = flow
        .post(
            &app,
            &[
                ("step", "register"),
                ("assignment", &assignment),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
        )
        .await;
    let code = query(&location(&reply.headers), "code").unwrap();
    let token = |basic: Option<&str>, extra: &[(&str, &str)]| {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", OPEN_CALLBACK),
        ];
        if !extra.iter().any(|(name, _)| *name == "code_verifier") {
            pairs.push(("code_verifier", VERIFIER));
        }
        pairs.extend_from_slice(extra);
        let mut request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(basic) = basic {
            request = request.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(basic)),
            );
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        request.body(Body::from(body)).unwrap()
    };
    // None of these is a client the endpoint knows: each is refused before the
    // code is touched, so the code is still good afterwards.
    for refused in [
        // a public client that presents a secret, in either place
        token(Some(&format!("open-app:{SECRET}")), &[]),
        token(
            None,
            &[("client_id", "open-app"), ("client_secret", SECRET)],
        ),
        // no client at all
        token(None, &[]),
        // an unknown client
        token(None, &[("client_id", "nobody")]),
    ] {
        assert_eq!(send(&app, refused).await.status, StatusCode::UNAUTHORIZED);
    }
    // A confidential client may not drop its secret to look public.
    let impostor = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={ONE_CALLBACK}&code_verifier={VERIFIER}&client_id=nilx-one"
        )))
        .unwrap();
    assert_eq!(send(&app, impostor).await.status, StatusCode::UNAUTHORIZED);

    // A wrong verifier spends the code and issues nothing.
    let wrong = format!("{VERIFIER}x");
    let forged = send(
        &app,
        token(
            None,
            &[("client_id", "open-app"), ("code_verifier", &wrong)],
        ),
    )
    .await;
    assert_eq!(forged.status, StatusCode::BAD_REQUEST, "{}", forged.body);
    assert!(forged.body.contains("invalid_grant"));

    // The right verifier on a fresh code is accepted, and Core's own verifier
    // accepts the token.
    let flow = open(&app, "open-app", OPEN_CALLBACK, None).await;
    let page = flow
        .post(&app, &[("step", "identify"), ("slug", "wanderer")])
        .await;
    let signed = flow
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", &hidden(&page.body, "pub_dress")),
                ("password", PASSWORD),
            ],
        )
        .await;
    let verified = flow
        .verified(&app, &signed)
        .await
        .expect("Core accepts the token");
    assert_eq!(
        verified.pub_dress, None,
        "the client did not ask for the address"
    );
}

#[tokio::test]
async fn health_styles_and_discovery_are_served() {
    let app = app().await;
    assert_eq!(send(&app, get("/healthz")).await.body, "ok\n");
    assert!(
        send(&app, get("/static/auth.css"))
            .await
            .body
            .contains("ecosystem-auth-panel")
    );
    assert_eq!(send(&app, get("/nope")).await.status, StatusCode::NOT_FOUND);
    let discovery: serde_json::Value = serde_json::from_str(
        &send(&app, get("/.well-known/openid-configuration"))
            .await
            .body,
    )
    .unwrap();
    assert_eq!(discovery["issuer"], ISSUER);
    assert_eq!(
        discovery["subject_types_supported"],
        serde_json::json!(["pairwise"])
    );
    let keys: serde_json::Value =
        serde_json::from_str(&send(&app, get("/.well-known/jwks.json")).await.body).unwrap();
    assert_eq!(keys["keys"][0]["crv"], "Ed25519");
    assert!(
        keys["keys"][0].get("d").is_none(),
        "the private key never leaves"
    );
}

// ---------------------------------------------------------------------------
// Product tokens (hub.v1)
// ---------------------------------------------------------------------------

fn product_assertion(seed: [u8; 32], kid: &str, client: &str, jti: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    crate::product_token::tests::assertion(
        &ed25519_dalek::SigningKey::from_bytes(&seed),
        kid,
        &serde_json::json!({
            "iss": client, "sub": client, "aud": format!("{ISSUER}/token"),
            "iat": now, "exp": now + 120, "jti": jti,
        }),
    )
}

async fn ask_product_token(app: &Router, fields: &[(&str, &str)]) -> Reply {
    let mut all = vec![
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
    ];
    all.extend_from_slice(fields);
    send(app, post_form("/token", "", &all)).await
}

fn token_claims(token: &str) -> (serde_json::Value, serde_json::Value) {
    let decode = |part: &str| -> serde_json::Value {
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap(),
        )
        .unwrap()
    };
    let mut parts = token.split('.');
    (decode(parts.next().unwrap()), decode(parts.next().unwrap()))
}

#[tokio::test]
async fn a_product_gets_a_token_for_the_hub_with_its_own_key() {
    let app = app().await;
    let assertion = product_assertion(MARKET_KEY, "m1", "0xda-market", "market-assertion-0001");
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &assertion),
            ("audience", "prism-hub"),
            ("scope", "hub.call"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["scope"], "hub.call");
    let token = body["access_token"].as_str().unwrap();
    let (header, claims) = token_claims(token);
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], "0xda-market");
    assert_eq!(claims["aud"], "prism-hub");
    assert_eq!(claims["scope"], "hub.call");
    assert!(claims.get("act").is_none());
    // Signed with the key AIS publishes, like every token it issues.
    let jwks: serde_json::Value =
        serde_json::from_str(&send(&app, get("/.well-known/jwks.json")).await.body).unwrap();
    let x = jwks["keys"][0]["x"].as_str().unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let signature = ed25519_dalek::Signature::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap(),
    )
    .unwrap();
    key.verify_strict(signed.as_bytes(), &signature).unwrap();

    // No scope asked: every scope granted for that audience.
    let assertion = product_assertion(MARKET_KEY, "m1", "0xda-market", "market-assertion-0002");
    let reply = ask_product_token(
        &app,
        &[("client_assertion", &assertion), ("audience", "prism-hub")],
    )
    .await;
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(
        body["scope"],
        "bond.profile.read hub.call hub.events telegram.special.purchase"
    );
}

#[tokio::test]
async fn an_assertion_buys_one_token_only() {
    let app = app().await;
    let assertion = product_assertion(MARKET_KEY, "m1", "0xda-market", "market-assertion-once");
    let fields = [
        ("client_assertion", assertion.as_str()),
        ("audience", "prism-hub"),
    ];
    assert_eq!(
        ask_product_token(&app, &fields).await.status,
        StatusCode::OK
    );
    let replay = ask_product_token(&app, &fields).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert!(replay.body.contains("invalid_client"));
}

#[tokio::test]
async fn a_product_token_is_refused_outside_the_registry() {
    let app = app().await;
    let market = |jti: &str| product_assertion(MARKET_KEY, "m1", "0xda-market", jti);
    // Another product's key, or a key under another product's name.
    let forged = product_assertion(HUB_KEY, "m1", "0xda-market", "forged-assertion-01");
    let reply = ask_product_token(
        &app,
        &[("client_assertion", &forged), ("audience", "prism-hub")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // A client that is not a product cannot use this grant at all.
    let not_product = product_assertion(MARKET_KEY, "m1", "nilx-one", "not-a-product-0001");
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &not_product),
            ("audience", "prism-hub"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // An audience or a scope that is not granted.
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &market("market-assertion-aud1")),
            ("audience", "nilx-one"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("invalid_target"));
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &market("market-assertion-scp1")),
            ("audience", "prism-hub"),
            ("scope", "wallet.debit"),
        ],
    )
    .await;
    assert!(reply.body.contains("invalid_scope"));
    // A product that is not a relay cannot name another product.
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &market("market-assertion-act1")),
            ("audience", "prism-hub"),
            ("actor", "prism-hub"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    // A secret is never accepted for this grant.
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &market("market-assertion-sec1")),
            ("audience", "prism-hub"),
            ("client_secret", SECRET),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // The refusals above did not spend the assertions that were sound.
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &market("market-assertion-aud1")),
            ("audience", "prism-hub"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
async fn the_hub_acts_for_a_product_it_relays() {
    let app = app().await;
    let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", "hub-assertion-relay-01");
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &assertion),
            ("audience", "0xda-market"),
            ("actor", "0xda-market"),
        ],
    )
    .await;
    // The relay names the product whose request it carries; the target
    // trusts the hub and still knows who asked.
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (_, claims) = token_claims(body["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], "prism-hub");
    assert_eq!(claims["act"]["sub"], "0xda-market");
    // An actor that is not a registered product is refused.
    let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", "hub-assertion-relay-02");
    let reply = ask_product_token(
        &app,
        &[
            ("client_assertion", &assertion),
            ("audience", "0xda-market"),
            ("actor", "open-app"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Person passes (hub.v1)
// ---------------------------------------------------------------------------

/// The hub's token for asking AIS for a pass on behalf of `actor`.
async fn hub_pass_token(app: &Router, actor: &str, jti: &str) -> String {
    let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", jti);
    let reply = ask_product_token(
        app,
        &[
            ("client_assertion", &assertion),
            ("audience", "ais"),
            ("actor", actor),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    body["access_token"].as_str().unwrap().to_owned()
}

async fn ask_pass(app: &Router, token: &str, body: serde_json::Value) -> Reply {
    send(
        app,
        Request::post("/family/pass")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn a_pass_names_the_person_to_another_product_and_back() {
    let app = app().await;
    let (flow, reply) = register_cell(&app, "f", "passholder").await;
    let one_sub = flow.verified(&app, &reply).await.expect("verified").subject;

    // 0x1 names the person by its own subject; the pass is for the market.
    let token = hub_pass_token(&app, "nilx-one", "hub-pass-token-0001").await;
    let reply = ask_pass(
        &app,
        &token,
        serde_json::json!({ "subject": one_sub, "audience": "0xda-market", "purpose": "order:o-42" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["expires_in"], 900);
    let (header, claims) = token_claims(body["pass"].as_str().unwrap());
    assert_eq!(header["typ"], "pass+jwt");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], "0xda-market");
    assert_eq!(claims["azp"], "nilx-one");
    assert_eq!(claims["purpose"], "order:o-42");
    let market_sub = claims["sub"].as_str().unwrap().to_owned();
    assert_ne!(
        market_sub, one_sub,
        "each product knows the person by its own subject"
    );

    // The market can now name the same person back to 0x1, by its own subject.
    let token = hub_pass_token(&app, "0xda-market", "hub-pass-token-0002").await;
    let reply = ask_pass(
        &app,
        &token,
        serde_json::json!({ "subject": market_sub, "audience": "nilx-one", "purpose": "claims" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (_, claims) = token_claims(body["pass"].as_str().unwrap());
    assert_eq!(claims["sub"], one_sub);
}

#[tokio::test]
async fn a_pass_is_refused_outside_its_rules() {
    let app = app().await;
    let (flow, reply) = register_cell(&app, "f", "passrules").await;
    let one_sub = flow.verified(&app, &reply).await.expect("verified").subject;
    let token = hub_pass_token(&app, "nilx-one", "hub-pass-token-0003").await;
    let request = |audience: &str, purpose: &str, subject: &str| serde_json::json!({ "subject": subject, "audience": audience, "purpose": purpose });

    // A subject AIS never gave this product.
    let reply = ask_pass(
        &app,
        &token,
        request("0xda-market", "claims", &"a".repeat(43)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(reply.body.contains("unknown_subject"));
    // The 0x1 subject is not the market's: the same subject named by the
    // market is unknown.
    let market_token = hub_pass_token(&app, "0xda-market", "hub-pass-token-0004").await;
    let reply = ask_pass(&app, &market_token, request("nilx-one", "claims", &one_sub)).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    // A pass to the asker itself, to a client that is not a product, or for
    // a purpose outside the protocol.
    for body in [
        request("nilx-one", "claims", &one_sub),
        request("open-app", "claims", &one_sub),
        request("0xda-market", "anything", &one_sub),
        request("0xda-market", "claims", "short"),
    ] {
        let reply = ask_pass(&app, &token, body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }

    // Only the relay's AIS token, with an actor, opens this door.
    let no_actor = {
        let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", "hub-pass-token-0005");
        let reply = ask_product_token(
            &app,
            &[("client_assertion", &assertion), ("audience", "ais")],
        )
        .await;
        let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    };
    let other_audience = {
        let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", "hub-pass-token-0006");
        let reply = ask_product_token(
            &app,
            &[
                ("client_assertion", &assertion),
                ("audience", "0xda-market"),
                ("actor", "nilx-one"),
            ],
        )
        .await;
        let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    };
    let mut tampered = token.clone();
    tampered.pop();
    tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
    for bad in [
        no_actor.as_str(),
        other_audience.as_str(),
        tampered.as_str(),
        "not-a-token",
    ] {
        let reply = ask_pass(&app, bad, request("0xda-market", "claims", &one_sub)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{bad}");
    }
    // A product that is not a relay cannot get a token for AIS at all.
    let assertion = product_assertion(MARKET_KEY, "m1", "0xda-market", "market-pass-token-01");
    let reply = ask_product_token(
        &app,
        &[("client_assertion", &assertion), ("audience", "ais")],
    )
    .await;
    assert!(reply.body.contains("invalid_target"));
}

// ---------------------------------------------------------------------------
// The family link (hub.v1)
// ---------------------------------------------------------------------------

async fn hub_token_with_scope(app: &Router, actor: &str, jti: &str, scope: &str) -> String {
    let assertion = product_assertion(HUB_KEY, "h1", "prism-hub", jti);
    let reply = ask_product_token(
        app,
        &[
            ("client_assertion", &assertion),
            ("audience", "ais"),
            ("actor", actor),
            ("scope", scope),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    body["access_token"].as_str().unwrap().to_owned()
}

async fn post_json(app: &Router, path: &str, token: &str, body: serde_json::Value) -> Reply {
    send(
        app,
        Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A person signed into 0x1, and the subject the market knows them by.
async fn person_in_both(app: &Router, slug: &str, n: u32) -> (String, String) {
    person_in_both_as(app, "nilx-one", slug, n).await
}

async fn person_in_both_as(
    app: &Router,
    client: &'static str,
    slug: &str,
    n: u32,
) -> (String, String) {
    let (flow, reply) = register_cell_for(app, client, "f", slug).await;
    let one_sub = flow.verified(app, &reply).await.expect("verified").subject;
    let token = hub_pass_token(app, client, &format!("hub-link-pass-{n:08}")).await;
    let reply = ask_pass(
        app,
        &token,
        serde_json::json!({ "subject": one_sub, "audience": "0xda-market", "purpose": "claims" }),
    )
    .await;
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (_, claims) = token_claims(body["pass"].as_str().unwrap());
    (one_sub, claims["sub"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn registered_bond_profile_uses_one_priv_id_across_products() {
    use serde_json::{Value, json};

    let dir = tempfile::tempdir().unwrap();
    let database = format!("sqlite://{}", dir.path().join("ais.sqlite").display());
    let app = app_with_store(Store::connect(&database).await.unwrap());
    let (one_sub, market_sub) = person_in_both_as(&app, "0x1", "sharedprofile", 91).await;
    let (_, other_market_sub) = person_in_both_as(&app, "0x1", "otherprofile", 92).await;
    let one_read =
        hub_token_with_scope(&app, "0x1", "profile-one-read-0001", "bond.profile.read").await;
    let one_write =
        hub_token_with_scope(&app, "0x1", "profile-one-write-0001", "bond.profile.write").await;
    let market_read = hub_token_with_scope(
        &app,
        "0xda-market",
        "profile-market-read-0001",
        "bond.profile.read",
    )
    .await;
    let market_write = hub_token_with_scope(
        &app,
        "0xda-market",
        "profile-market-write-0001",
        "bond.profile.write",
    )
    .await;

    let profile = "/family/bond/profile";
    let context = "/family/bond/context";
    let initial = post_json(&app, profile, &one_read, json!({ "subject": one_sub })).await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.body);
    assert_eq!(initial.headers[header::CACHE_CONTROL], "no-store");
    let first: Value = serde_json::from_str(&initial.body).unwrap();
    let id = first["priv_id"].as_str().unwrap();
    assert!(id.starts_with("bond_"));
    assert_eq!(id.len(), 69);
    assert_eq!(first["pub_dress"], "0xfsharedprofile");
    assert_eq!(first["revision"], 0);
    assert!(first["localization"].is_null());
    assert!(first["location"].is_null());

    // The base location is one H3 cell at resolution 8 (Kyiv, Maidan).
    let cell = h3o::LatLng::new(50.4501, 30.5234)
        .unwrap()
        .to_cell(h3o::Resolution::Eight);
    let location = json!(format!("{:x}", u64::from(cell)));
    let update = json!({ "subject": one_sub, "priv_id": id, "expected_revision": 0,
                         "localization": "uk-UA", "location": location });
    let reply = post_json(&app, context, &one_write, update.clone()).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let updated: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(updated["priv_id"], id);
    assert_eq!(updated["pub_dress"], first["pub_dress"]);
    assert_eq!(updated["localization"], "uk-UA");
    assert_eq!(updated["location"], location);
    assert_eq!(updated["revision"], 1);

    let market_query = json!({ "subject": market_sub, "priv_id": id });
    let reply = post_json(&app, profile, &market_read, market_query.clone()).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(serde_json::from_str::<Value>(&reply.body).unwrap(), updated);

    assert_eq!(
        post_json(&app, context, &one_write, update).await.status,
        StatusCode::CONFLICT
    );
    // A precise position, or a cell at any other resolution, never reaches AIS.
    let finer = format!(
        "{:x}",
        u64::from(cell.center_child(h3o::Resolution::Nine).unwrap())
    );
    for precise in [
        json!({ "latitude_e7": "504500000", "longitude_e7": "305234000" }),
        json!(finer),
        json!("50.4501,30.5234"),
    ] {
        let refused = post_json(
            &app,
            context,
            &one_write,
            json!({ "subject": one_sub, "priv_id": id, "expected_revision": 1,
                    "localization": "uk-UA", "location": precise }),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{precise}"
        );
    }
    assert_eq!(
        post_json(
            &app,
            profile,
            &market_read,
            json!({ "subject": other_market_sub, "priv_id": id })
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post_json(&app, profile, &market_read, json!({ "priv_id": id }))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        post_json(&app, profile, "invalid", market_query)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(
            &app,
            context,
            &market_write,
            json!({ "subject": market_sub, "priv_id": id,
                   "expected_revision": 1, "localization": null, "location": null })
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(
            &app,
            context,
            &one_write,
            json!({ "subject": one_sub, "priv_id": id,
                   "expected_revision": 1, "localization": "en-GB" })
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let cleared = post_json(
        &app,
        context,
        &one_write,
        json!({ "subject": one_sub,
            "priv_id": id, "expected_revision": 1, "localization": "en-GB", "location": null }),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.body);
    let cleared: Value = serde_json::from_str(&cleared.body).unwrap();
    assert_eq!(cleared["priv_id"], id);
    assert_eq!(cleared["localization"], "en-GB");
    assert_eq!(cleared["revision"], 2);
    assert!(cleared["location"].is_null());

    // Model an authoritative address edit and service restart. The profile
    // must read the registry's current address using the same private ID.
    drop(app);
    let pool = sqlx::SqlitePool::connect(&database).await.unwrap();
    let changed = sqlx::query(
        "UPDATE identities SET pub_dress = '0xfupdatedprofile', label = '0xfupdatedprofile' \
         WHERE pub_dress = '0xfsharedprofile'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    // `priv_id` is its own random value, never the private subject.
    let exposed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities WHERE 'bond_' || lower(hex(subject)) = ?",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(exposed, 0);
    let assigned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bond_ids WHERE 'bond_' || lower(hex(priv_id)) = ?",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(assigned, 1);
    assert!(
        sqlx::query("UPDATE bond_ids SET priv_id = zeroblob(32)")
            .execute(&pool)
            .await
            .is_err(),
        "priv_id must be immutable"
    );
    pool.close().await;
    let restarted = app_with_store(Store::connect(&database).await.unwrap());
    let reply = post_json(
        &restarted,
        profile,
        &market_read,
        json!({ "subject": market_sub, "priv_id": id }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let persisted: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(persisted["priv_id"], id);
    assert_eq!(persisted["pub_dress"], "0xfupdatedprofile");
    assert_eq!(persisted["localization"], "en-GB");
    assert_eq!(persisted["revision"], 2);
    assert!(persisted["location"].is_null());
}

#[tokio::test]
async fn ais_tells_the_market_which_bond_a_person_is() {
    let app = app().await;
    let (one_sub, market_sub) = person_in_both(&app, "linkholder", 1).await;
    let now = unix_now();

    // 0x1 reports its Bond for the person, by its own subject.
    let one = hub_token_with_scope(&app, "nilx-one", "hub-link-tok-00001", "accounts.put").await;
    let report = |account: &str, pub_dress: &str, as_of: u64| serde_json::json!({ "subject": one_sub, "account": account, "pub_dress": pub_dress, "as_of": as_of });
    let reply = post_json(
        &app,
        "/family/accounts",
        &one,
        report("bond-7f3a", "0xflinkholder", now - 10),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.body.contains("stored"));

    // The market asks once, by its own subject, and learns the Bond.
    let market = hub_token_with_scope(&app, "0xda-market", "hub-link-tok-00002", "link.read").await;
    let ask = serde_json::json!({ "subject": market_sub, "product": "nilx-one" });
    let reply = post_json(&app, "/family/link", &market, ask.clone()).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["sub"], market_sub);
    assert_eq!(body["accounts"]["nilx-one"]["account"], "bond-7f3a");
    assert_eq!(body["accounts"]["nilx-one"]["pub_dress"], "0xflinkholder");
    assert!(!reply.body.contains(&one_sub), "never 0x1's own subject");

    // A replay of an older report changes nothing; a newer one (a rename) does.
    let reply = post_json(
        &app,
        "/family/accounts",
        &one,
        report("bond-7f3a", "0xfold", now - 20),
    )
    .await;
    assert!(reply.body.contains("stale"), "{}", reply.body);
    let reply = post_json(
        &app,
        "/family/accounts",
        &one,
        report("bond-7f3a", "0x0renamed", now),
    )
    .await;
    assert!(reply.body.contains("stored"), "{}", reply.body);
    let reply = post_json(&app, "/family/link", &market, ask).await;
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["accounts"]["nilx-one"]["pub_dress"], "0x0renamed");
}

#[tokio::test]
async fn a_link_is_written_only_by_its_product_and_read_only_with_the_scope() {
    let app = app().await;
    let (one_sub, market_sub) = person_in_both(&app, "linkrules", 2).await;
    let (other_sub, _) = person_in_both(&app, "linkother", 3).await;
    let now = unix_now();
    let one = hub_token_with_scope(&app, "nilx-one", "hub-link-tok-00003", "accounts.put").await;
    let report = |subject: &str, account: &str| serde_json::json!({ "subject": subject, "account": account, "pub_dress": "0xflinkrules", "as_of": now });
    assert_eq!(
        post_json(&app, "/family/accounts", &one, report(&one_sub, "bond-1"))
            .await
            .status,
        StatusCode::OK
    );

    // One Bond, one person.
    let reply = post_json(&app, "/family/accounts", &one, report(&other_sub, "bond-1")).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);

    // The market cannot write a 0x1 link: what it reports is its own account,
    // and the person it names must be one AIS gave it.
    let market_writes =
        hub_token_with_scope(&app, "0xda-market", "hub-link-tok-00004", "accounts.put").await;
    let reply = post_json(
        &app,
        "/family/accounts",
        &market_writes,
        report(&one_sub, "bond-2"),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::NOT_FOUND,
        "0x1's subject is unknown to the market"
    );

    // Malformed reports.
    for bad in [
        serde_json::json!({ "subject": one_sub, "account": "bond 1", "pub_dress": "0xflinkrules", "as_of": now }),
        serde_json::json!({ "subject": one_sub, "account": "bond-1", "pub_dress": "not-an-address", "as_of": now }),
        serde_json::json!({ "subject": one_sub, "account": "bond-1", "pub_dress": "0xflinkrules", "as_of": now + 3600 }),
        serde_json::json!({ "subject": "short", "account": "bond-1", "pub_dress": "0xflinkrules", "as_of": now }),
    ] {
        let reply = post_json(&app, "/family/accounts", &one, bad.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }

    // Reading needs link.read; writing needs accounts.put.
    let reply = post_json(
        &app,
        "/family/link",
        &market_writes,
        serde_json::json!({ "subject": market_sub, "product": "nilx-one" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let market = hub_token_with_scope(&app, "0xda-market", "hub-link-tok-00005", "link.read").await;
    let reply = post_json(
        &app,
        "/family/accounts",
        &market,
        report(&market_sub, "bond-3"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // Unknown answers, and a question about the asker itself.
    let ask = |subject: &str, product: &str| serde_json::json!({ "subject": subject, "product": product });
    let reply = post_json(
        &app,
        "/family/link",
        &market,
        ask(&"a".repeat(43), "nilx-one"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = post_json(&app, "/family/link", &market, ask(&market_sub, "prism-hub")).await;
    assert_eq!(
        reply.status,
        StatusCode::NOT_FOUND,
        "no prism-hub account was reported"
    );
    let reply = post_json(
        &app,
        "/family/link",
        &market,
        ask(&market_sub, "0xda-market"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = post_json(&app, "/family/link", &market, ask(&market_sub, "open-app")).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "not a product");
}

#[tokio::test]
async fn telegram_purchase_requires_a_current_link_and_a_scoped_market() {
    let app = app().await;
    let (legacy, _) = person_in_both(&app, "telegrambuyer", 41).await;
    let pass_token = hub_pass_token(&app, "nilx-one", "telegram-person-pass-1").await;
    let reply = ask_pass(
        &app,
        &pass_token,
        serde_json::json!({ "subject": legacy, "audience": "0x1", "purpose": "claims" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (_, claims) = token_claims(body["pass"].as_str().unwrap());
    let sub = claims["sub"].as_str().unwrap();
    let registrar =
        hub_token_with_scope(&app, "0x1", "telegram-register-tok", "telegram.link.put").await;
    let market = hub_token_with_scope(
        &app,
        "0xda-market",
        "telegram-market-tok",
        "telegram.special.purchase",
    )
    .await;
    let ungranted = hub_token_with_scope(
        &app,
        "0xda-market",
        "telegram-ungranted-link",
        "telegram.link.put",
    )
    .await;
    let link = |id: Option<i64>, revision: i64| serde_json::json!({"subject": sub, "telegram_id": id, "revision": revision});
    let order = serde_json::json!({
        "telegram_id": 987654321,
        "order_id": "market-order-1",
        "sku": "0x1_special_1m",
        "quantity": 1,
        "price_id": 42,
        "amount_minor": 640
    });

    let reply = post_json(
        &app,
        "/family/telegram-link",
        &ungranted,
        link(Some(987654321), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        serde_json::json!({ "subject": sub, "revision": 1 }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);

    let reply = post_json(&app, "/family/telegram-purchase", &market, order.clone()).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(reply.body.contains("telegram_unlinked"));

    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(Some(987654321), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = post_json(
        &app,
        "/family/accounts",
        &registrar,
        serde_json::json!({
            "subject": sub, "account": "bond-telegram", "pub_dress": "0xftelegrambuyer",
            "as_of": unix_now()
        }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let account = hub_token_with_scope(&app, "0x1", "telegram-account-tok", "accounts.put").await;
    let reply = post_json(
        &app,
        "/family/accounts",
        &account,
        serde_json::json!({
            "subject": sub, "account": "bond-telegram", "pub_dress": "0xftelegrambuyer",
            "as_of": unix_now()
        }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

    let mut wrong = order.clone();
    wrong["quantity"] = 2.into();
    let reply = post_json(&app, "/family/telegram-purchase", &market, wrong).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = post_json(&app, "/family/telegram-purchase", &market, order.clone()).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (header, claims) = token_claims(body["permit"].as_str().unwrap());
    assert_eq!(header["typ"], "purchase+jwt");
    assert_eq!(claims["sub"], sub);
    assert_eq!(claims["aud"], "0x1");
    assert_eq!(claims["azp"], "0xda-market");
    assert_eq!(claims["order_id"], "market-order-1");
    assert_eq!(claims["price_id"], 42);
    assert_eq!(claims["amount_minor"], 640);

    let reply = post_json(&app, "/family/telegram-link", &registrar, link(None, 2)).await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(Some(987654321), 1),
    )
    .await;
    assert!(reply.body.contains("stale"));
    let reply = post_json(&app, "/family/telegram-purchase", &market, order).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_telegram_account_belongs_to_one_person_and_only_0x1_reports_it() {
    let app = app().await;
    let subject_of = |sub: &str| sub.to_owned();
    let mut subs = Vec::new();
    for (slug, n) in [("telegramfirst", 43_u32), ("telegramsecond", 44)] {
        let (legacy, _) = person_in_both(&app, slug, n).await;
        let pass_token =
            hub_pass_token(&app, "nilx-one", &format!("telegram-owner-pass-{n}")).await;
        let reply = ask_pass(
            &app,
            &pass_token,
            serde_json::json!({ "subject": legacy, "audience": "0x1", "purpose": "claims" }),
        )
        .await;
        let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        let (_, claims) = token_claims(body["pass"].as_str().unwrap());
        subs.push(subject_of(claims["sub"].as_str().unwrap()));
    }
    let registrar =
        hub_token_with_scope(&app, "0x1", "telegram-owner-reg-1", "telegram.link.put").await;
    let partner =
        hub_token_with_scope(&app, "partner", "telegram-partner-1", "telegram.link.put").await;
    let link = |sub: &str, id: serde_json::Value, revision: i64| serde_json::json!({"subject": sub, "telegram_id": id, "revision": revision});

    // A product with the scope that is not 0x1 cannot write a binding.
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &partner,
        link(&subs[0], 555.into(), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(reply.body.contains("invalid_actor"));

    // One Telegram account, one person.
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(&subs[0], 555.into(), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(&subs[1], 555.into(), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert!(reply.body.contains("account_taken"));

    // A report older than the stored revision is stale, not a conflict.
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(&subs[0], 555.into(), 1),
    )
    .await;
    assert!(reply.body.contains("stale"));

    // After the first person disconnects, the account can move on.
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(&subs[0], serde_json::Value::Null, 2),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        link(&subs[1], 555.into(), 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Telegram provider evidence for the Core-owned product Gateway.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn telegram_identity_proof_requires_direct_scoped_token_and_existing_bond() {
    let app = app().await;
    let (legacy, _) = person_in_both(&app, "tgidentity", 66).await;
    let pass = hub_pass_token(&app, "nilx-one", "tgidentity-pass-01").await;
    let reply = ask_pass(
        &app,
        &pass,
        serde_json::json!({ "subject": legacy, "audience": "0x1", "purpose": "claims" }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let raw: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let (_, claims) = token_claims(raw["pass"].as_str().unwrap());
    let sub = claims["sub"].as_str().unwrap();

    // The direct AIS token uses a product key, no shared HMAC or Bot Token.
    let assertion = product_assertion(ONE_KEY, "o1", "0x1", "telegram-direct-proof-01");
    let token = ask_product_token(
        &app,
        &[
            ("client_assertion", &assertion),
            ("client_id", "0x1"),
            ("audience", "ais"),
            ("scope", "telegram.identity.resolve"),
        ],
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let payload: serde_json::Value = serde_json::from_str(&token.body).unwrap();
    let token = payload["access_token"].as_str().unwrap();
    let nonce = "abcdefghijklmnopABCDEFGHIJKLMNOP";
    let request = serde_json::json!({ "telegram_id": 656565, "nonce": nonce });

    // Even with a valid service credential, no provider link means no proof.
    let missing = post_json(&app, "/family/telegram-identity", token, request.clone()).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.body.contains("telegram_unlinked"));

    // Record a linked Telegram provider and its *existing* 0x1 product account.
    let registrar =
        hub_token_with_scope(&app, "0x1", "tgidentity-register-01", "telegram.link.put").await;
    let recorded = post_json(
        &app,
        "/family/telegram-link",
        &registrar,
        serde_json::json!({ "subject": sub, "telegram_id": 656565, "revision": 1 }),
    )
    .await;
    assert_eq!(recorded.status, StatusCode::OK, "{}", recorded.body);
    let missing_bond = post_json(&app, "/family/telegram-identity", token, request.clone()).await;
    assert_eq!(missing_bond.status, StatusCode::NOT_FOUND);
    assert!(missing_bond.body.contains("bond_unlinked"));

    let account = hub_token_with_scope(&app, "0x1", "tgidentity-account-01", "accounts.put").await;
    let recorded = post_json(
        &app,
        "/family/accounts",
        &account,
        serde_json::json!({
            "subject": sub,
            "account": "bond-tg-identity",
            "pub_dress": "0xftgidentity",
            "as_of": unix_now()
        }),
    )
    .await;
    assert_eq!(recorded.status, StatusCode::OK, "{}", recorded.body);

    let proof = post_json(&app, "/family/telegram-identity", token, request.clone()).await;
    assert_eq!(proof.status, StatusCode::OK, "{}", proof.body);
    assert_eq!(proof.headers[header::CACHE_CONTROL], "no-store");
    assert!(
        !proof.body.contains("656565"),
        "no raw Telegram ID in response"
    );
    let body: serde_json::Value = serde_json::from_str(&proof.body).unwrap();
    assert_eq!(body["expires_in"], 120);
    assert!(
        body.get("session").is_none(),
        "proof cannot open a Core session"
    );
    let signed = body["proof"].as_str().unwrap();
    let (header, claims) = token_claims(signed);
    assert_eq!(header["typ"], "provider-evidence+jwt");
    assert_eq!(claims["aud"], "0x1");
    assert_eq!(claims["azp"], "0x1");
    assert_eq!(claims["provider"], "telegram");
    assert_eq!(claims["purpose"], "telegram.identity.resolve");
    assert_eq!(claims["nonce"], nonce);
    assert_eq!(claims["sub"], sub);
    assert!(claims.get("telegram_id").is_none());
    assert!(claims.get("active_client").is_none());
    assert!(claims["exp"].as_u64().unwrap() > unix_now());

    let jwks: serde_json::Value =
        serde_json::from_str(&send(&app, get("/.well-known/jwks.json")).await.body).unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwks["keys"][0]["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let (message, signature) = signed.rsplit_once('.').unwrap();
    let signature = ed25519_dalek::Signature::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap(),
    )
    .unwrap();
    key.verify_strict(message.as_bytes(), &signature).unwrap();

    // A Prism relay or absent credential can never use this direct product route.
    let relay = hub_token_with_scope(&app, "0x1", "tgidentity-relay-01", "telegram.link.put").await;
    for invalid in ["", relay.as_str(), "invalid"] {
        let response = post_json(&app, "/family/telegram-identity", invalid, request.clone()).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    let invalid_request = post_json(
        &app,
        "/family/telegram-identity",
        token,
        serde_json::json!({ "telegram_id": 656565, "nonce": "short" }),
    )
    .await;
    assert_eq!(invalid_request.status, StatusCode::BAD_REQUEST);
}

fn binding_authorize_url(
    client_id: &str,
    callback: &str,
    scope: &str,
    nonce: &str,
    hint: Option<&str>,
) -> String {
    let mut url = Url::parse(&format!("{ISSUER}/authorize")).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", callback)
        .append_pair("scope", scope)
        .append_pair("state", "the-state")
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &code_challenge(VERIFIER))
        .append_pair("code_challenge_method", "S256");
    if let Some(hint) = hint {
        url.query_pairs_mut()
            .append_pair("telegram_binding_hint", hint);
    }
    format!("/authorize?{}", url.query().unwrap())
}

/// Signs in to 0x1 on the Telegram callback and returns the raw ID token.
async fn telegram_sign_in_token(app: &Router, nonce: &str, hint: Option<&str>) -> String {
    telegram_sign_in_token_with_exchange_hint(app, nonce, hint, hint).await
}

async fn telegram_sign_in_token_with_exchange_hint(
    app: &Router,
    nonce: &str,
    hint: Option<&str>,
    exchange_hint: Option<&str>,
) -> String {
    let scope = if hint.is_some() {
        "openid pub_dress telegram_binding"
    } else {
        "openid pub_dress"
    };
    let reply = send(
        app,
        get(&binding_authorize_url(
            "0x1",
            TELEGRAM_CALLBACK,
            scope,
            nonce,
            hint,
        )),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let flow = Flow {
        client_id: "0x1",
        callback: TELEGRAM_CALLBACK,
        nonce: nonce.to_owned(),
        request: hidden(&reply.body, "request"),
        cookie: set_cookie(&reply.headers, "__Host-ais_authz").expect("browser cookie"),
        page: reply.body,
    };
    let signed_in = flow
        .post(
            app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0bound"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let back = location(&signed_in.headers);
    let response = flow
        .exchange_with_binding(app, &query(&back, "code").unwrap(), exchange_hint)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let token: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    token["id_token"].as_str().unwrap().to_owned()
}

fn token_payload(token: &str) -> serde_json::Value {
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn the_telegram_binding_answers_only_whether_the_named_account_is_linked() {
    use crate::issuer::telegram_binding_hint as hint;
    // The same vector as nilx-one/core `telegram_binding_hint`.
    assert_eq!(
        hint("nonce-1", 4242),
        "UDbC6i0zJM5f9ja2EjMjAQ-06Jde25hEOetHxM5Ua6c"
    );
    let store = Store::connect("sqlite::memory:").await.expect("store");
    let app = app_with_store(store.clone());
    let (_, created) = register_cell(&app, "0", "bound").await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);

    // No Telegram account is linked yet: no claim, whatever the hint names.
    let nonce = "nonce-unlinked-telegram-1";
    let token = telegram_sign_in_token(&app, nonce, Some(&hint(nonce, 4242))).await;
    assert!(token_payload(&token).get("telegram_binding").is_none());

    let person = store
        .find(&<nilxone_contracts::PubDress as std::str::FromStr>::from_str("0x0bound").unwrap())
        .await
        .unwrap()
        .unwrap();
    store
        .put_telegram_link(&person.subject, Some(4242), 1)
        .await
        .unwrap();

    // The named account is the linked one: one bit, `true`.
    let nonce = "nonce-linked-telegram-12345";
    let named = hint(nonce, 4242);
    let token = telegram_sign_in_token(&app, nonce, Some(&named)).await;
    let claims = token_payload(&token);
    assert_eq!(claims["telegram_binding"], serde_json::Value::Bool(true));
    // Nothing derived from the linked account other than that bit.
    assert!(!token.contains(&named));
    assert!(!claims.to_string().contains("4242"));
    let known = [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "amr",
        "pub_dress",
        "telegram_binding",
    ];
    assert!(
        claims
            .as_object()
            .unwrap()
            .keys()
            .all(|key| known.contains(&key.as_str()))
    );

    // The original candidate must also be supplied at PKCE code exchange.
    let different = hint(nonce, 4243);
    for exchange_hint in [None, Some(different.as_str())] {
        let token =
            telegram_sign_in_token_with_exchange_hint(&app, nonce, Some(&named), exchange_hint)
                .await;
        assert!(token_payload(&token).get("telegram_binding").is_none());
    }

    // Another account, or the right account under another nonce: no claim.
    let nonce = "nonce-other-account-12345";
    let token = telegram_sign_in_token(&app, nonce, Some(&hint(nonce, 4243))).await;
    assert!(token_payload(&token).get("telegram_binding").is_none());
    let nonce = "nonce-replayed-hint-123456";
    let token = telegram_sign_in_token(&app, nonce, Some(&named)).await;
    assert!(token_payload(&token).get("telegram_binding").is_none());

    // Not asked for: no claim, even with a link.
    let token = telegram_sign_in_token(&app, "nonce-not-asked-for-1", None).await;
    assert!(token_payload(&token).get("telegram_binding").is_none());
}

#[tokio::test]
async fn the_telegram_binding_is_refused_outside_the_chat_login_context() {
    let app = app().await;
    let scope = "openid pub_dress telegram_binding";
    let nonce = "nonce-refused-context-1";
    let good_hint = crate::issuer::telegram_binding_hint(nonce, 42);
    for (client, callback, scope, hint, error) in [
        // 0x1's browser sign-in is not its Telegram chat login.
        (
            "0x1",
            ONE_CALLBACK,
            scope,
            Some(good_hint.as_str()),
            "invalid_scope",
        ),
        // A client without a Telegram chat login.
        (
            "nilx-one",
            ONE_CALLBACK,
            scope,
            Some(good_hint.as_str()),
            "invalid_scope",
        ),
        // The scope without a hint, a malformed hint, or a hint without it.
        ("0x1", TELEGRAM_CALLBACK, scope, None, "invalid_request"),
        (
            "0x1",
            TELEGRAM_CALLBACK,
            scope,
            Some("4242"),
            "invalid_request",
        ),
        (
            "0x1",
            TELEGRAM_CALLBACK,
            "openid pub_dress",
            Some(good_hint.as_str()),
            "invalid_request",
        ),
    ] {
        let refused = send(
            &app,
            get(&binding_authorize_url(client, callback, scope, nonce, hint)),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::SEE_OTHER,
            "{client} {callback}: {}",
            refused.body
        );
        assert_eq!(
            query(&location(&refused.headers), "error").as_deref(),
            Some(error),
            "{client} {callback} {scope} {hint:?}"
        );
    }
}

#[tokio::test]
async fn a_telegram_chat_login_page_hands_its_init_data_to_the_client_only() {
    let app = app().await;
    let (_, created) = register_cell(&app, "0", "bound").await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    let nonce = "nonce-telegram-init-data-1";
    let hint = crate::issuer::telegram_binding_hint(nonce, 42);
    let page = send(
        &app,
        get(&binding_authorize_url(
            "0x1",
            TELEGRAM_CALLBACK,
            "openid pub_dress telegram_binding",
            nonce,
            Some(&hint),
        )),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(r#"name="telegram_init_data""#));
    assert!(
        page.body
            .contains("https://telegram.org/js/telegram-web-app.js")
    );
    assert!(page.body.contains(r#"src="/static/telegram.js""#));
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self' https://telegram.org"),
        "{csp}"
    );

    // A browser sign-in has no script and no such field.
    let browser = open(&app, "0x1", ONE_CALLBACK, None).await;
    assert!(!browser.page.contains("telegram_init_data"));
    assert!(!browser.page.contains("<script"));

    let script = send(&app, get("/static/telegram.js")).await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(script.body.contains("Telegram.WebApp"));

    let flow = Flow {
        client_id: "0x1",
        callback: TELEGRAM_CALLBACK,
        nonce: nonce.to_owned(),
        request: hidden(&page.body, "request"),
        cookie: set_cookie(&page.headers, "__Host-ais_authz").expect("browser cookie"),
        page: page.body,
    };
    let init_data = "query_id=q&user=%7B%22id%22%3A42%7D&auth_date=1&hash=00";
    let signed_in = flow
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0bound"),
                ("password", PASSWORD),
                ("telegram_init_data", init_data),
            ],
        )
        .await;
    let back = location(&signed_in.headers);
    let response = flow.exchange(&app, &query(&back, "code").unwrap()).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let token: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(token["telegram_init_data"], init_data);
    // Never inside the signed ID token: AIS asserts nothing about it.
    assert!(!token["id_token"].as_str().unwrap().contains("query_id"));
    assert!(
        !token_payload(token["id_token"].as_str().unwrap())
            .to_string()
            .contains("query_id")
    );

    // A browser sign-in that posts the field anyway passes nothing on.
    let signed_in = browser
        .post(
            &app,
            &[
                ("step", "sign_in"),
                ("pub_dress", "0x0bound"),
                ("password", PASSWORD),
                ("telegram_init_data", init_data),
            ],
        )
        .await;
    let back = location(&signed_in.headers);
    let response = browser.exchange(&app, &query(&back, "code").unwrap()).await;
    let token: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert!(token.get("telegram_init_data").is_none());
}
