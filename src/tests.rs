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
const PRISM_CALLBACK: &str = "https://prism.aiaiaiai.org/auth/callback";
const SECRET: &str = "a-client-secret-of-thirty-two-bytes!";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "a-pkce-verifier-that-is-long-enough-for-rfc-7636";

fn hex_sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn app() -> Router {
    let clients = serde_json::json!([
        { "client_id": "nilx-one", "name": "0x1", "skin": "cell", "redirect_uris": [ONE_CALLBACK],
          "secret_sha256": hex_sha256(SECRET), "pub_dress": true },
        { "client_id": "prism", "name": "Prism", "skin": "slug", "redirect_uris": [PRISM_CALLBACK],
          "secret_sha256": hex_sha256(SECRET) },
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
    let store = Store::connect("sqlite::memory:").await.expect("store");
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
    let scope = if client_id == "nilx-one" {
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
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.callback),
                ("code_verifier", VERIFIER),
            ])
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                header::AUTHORIZATION,
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{SECRET}", self.client_id))
                ),
            )
            .body(Body::from(body))
            .unwrap();
        send(app, request).await
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
    let flow = open(app, "nilx-one", ONE_CALLBACK, None).await;
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
