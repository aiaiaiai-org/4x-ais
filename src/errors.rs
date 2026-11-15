// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Optional, non-blocking errors.v1 adapter for the independently hosted
//! 4x-errors collector. Never sends request payloads, token contents, or
//! tracing event fields (which can contain identity or password information).

use std::time::{Duration, SystemTime};

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{Layer, layer::Context};

const PROJECT: &str = "aiaiaiai-org/4x-ais";
const QUEUE_CAPACITY: usize = 64;

#[derive(Clone)]
pub struct Reporter {
    tx: mpsc::Sender<ErrorEvent>,
}

struct ReporterConfig {
    endpoint: Url,
    authorization: HeaderValue,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetupError {
    Incomplete,
    Endpoint,
    Token,
    HttpClient,
}

impl ReporterConfig {
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, SetupError> {
        let endpoint = get("AIS_ERRORS_ENDPOINT").filter(|v| !v.is_empty());
        let token = get("AIS_ERRORS_INGEST_TOKEN").filter(|v| !v.is_empty());
        let (Some(endpoint), Some(token)) = (endpoint, token) else {
            return if get("AIS_ERRORS_ENDPOINT").is_none()
                && get("AIS_ERRORS_INGEST_TOKEN").is_none()
            {
                Ok(None)
            } else {
                Err(SetupError::Incomplete)
            };
        };

        // Collector URL is an HTTPS origin, never a user-controlled request URL.
        let base = Url::parse(&endpoint).map_err(|_| SetupError::Endpoint)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(SetupError::Endpoint);
        }
        let endpoint = base.join("v1/events").map_err(|_| SetupError::Endpoint)?;

        // No log or error contains the token, even for malformed configuration.
        if token.len() < 32 || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(SetupError::Token);
        }
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| SetupError::Token)?;
        authorization.set_sensitive(true);

        Ok(Some(Self {
            endpoint,
            authorization,
        }))
    }
}

#[derive(Serialize)]
struct ErrorEvent {
    protocol_version: &'static str,
    event_id: String,
    error_id: &'static str,
    project: &'static str,
    source: &'static str,
    severity: &'static str,
    message: &'static str,
    full_text: &'static str,
    observed_at: String,
    context: serde_json::Value,
    tags: [&'static str; 2],
}

impl ErrorEvent {
    fn new(
        error_id: &'static str,
        source: &'static str,
        message: &'static str,
        context: serde_json::Value,
    ) -> Option<Self> {
        let mut uuid = [0u8; 16];
        getrandom::fill(&mut uuid).ok()?;
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        let event_id = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
        );
        let observed_at = DateTime::<Utc>::from(SystemTime::now())
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        Some(Self {
            protocol_version: "errors.v1",
            event_id,
            error_id,
            project: PROJECT,
            source,
            severity: "error",
            message,
            full_text: "AIS recorded an internal failure. Request bodies and event fields were omitted.",
            observed_at,
            context,
            tags: ["identity", "server"],
        })
    }
}

impl Reporter {
    /// No reporting configuration means a null reporter. Invalid opt-in
    /// configuration is an observable warning but never prevents sign-in.
    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, SetupError> {
        ReporterConfig::from_lookup(get)?
            .map(Self::start)
            .transpose()
    }

    fn start(config: ReporterConfig) -> Result<Self, SetupError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| SetupError::HttpClient)?;
        let (tx, mut rx) = mpsc::channel::<ErrorEvent>(QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let delivered = client
                    .post(config.endpoint.clone())
                    .header(AUTHORIZATION, config.authorization.clone())
                    .json(&event)
                    .send()
                    .await;
                if !matches!(delivered, Ok(ref response) if response.status().as_u16() == 201) {
                    // Only debug level, so a collector outage never feeds back
                    // into the ERROR event subscriber and causes recursion.
                    tracing::debug!("4x-errors delivery failed");
                }
            }
        });
        Ok(Self { tx })
    }

    fn enqueue(&self, event: Option<ErrorEvent>) {
        if let Some(event) = event {
            // A full queue or stopped worker is a telemetry failure only.
            let _ = self.tx.try_send(event);
        }
    }

    fn report_http(&self, status: u16, route: &str) {
        self.enqueue(ErrorEvent::new(
            "identity.http.serverfailure",
            "4x-ais.http",
            "AIS returned an HTTP server failure",
            serde_json::json!({"status": status, "route": route}),
        ));
    }

    pub fn layer(&self) -> ErrorLayer {
        ErrorLayer(self.clone())
    }
}

/// Applied to the production router only. The route comes from Axum's
/// matched template, never the full URI, query, or authorization header.
pub async fn report_http_errors(
    State(reporter): State<Reporter>,
    request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let response = next.run(request).await;
    if response.status().is_server_error() {
        reporter.report_http(response.status().as_u16(), &route);
    }
    response
}

pub struct ErrorLayer(Reporter);

impl<S: Subscriber> Layer<S> for ErrorLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() == Level::ERROR {
            // No visitor: the event's field values can carry user/identity data.
            self.0.enqueue(ErrorEvent::new(
                "identity.runtime.failure",
                "4x-ais.runtime",
                "AIS logged an internal error",
                serde_json::json!({"target": event.metadata().target()}),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    fn valid_config() -> Result<Option<ReporterConfig>, SetupError> {
        ReporterConfig::from_lookup(|key| match key {
            "AIS_ERRORS_ENDPOINT" => Some("https://errors.example.org/".to_owned()),
            "AIS_ERRORS_INGEST_TOKEN" => Some("t".repeat(64)),
            _ => None,
        })
    }

    #[test]
    fn configuration_requires_both_secure_values() {
        assert!(matches!(ReporterConfig::from_lookup(|_| None), Ok(None)));
        assert!(matches!(valid_config(), Ok(Some(_))));
        assert!(matches!(
            ReporterConfig::from_lookup(|key| (key == "AIS_ERRORS_ENDPOINT")
                .then(|| "https://errors.example.org".to_owned())),
            Err(SetupError::Incomplete)
        ));
        for endpoint in [
            "http://errors.example.org",
            "https://user:password@errors.example.org/",
            "https://errors.example.org/path",
            "https://errors.example.org/?token=unsafe",
        ] {
            assert!(matches!(
                ReporterConfig::from_lookup(|key| match key {
                    "AIS_ERRORS_ENDPOINT" => Some(endpoint.to_owned()),
                    "AIS_ERRORS_INGEST_TOKEN" => Some("t".repeat(64)),
                    _ => None,
                }),
                Err(SetupError::Endpoint)
            ));
        }
        assert!(matches!(
            ReporterConfig::from_lookup(|key| match key {
                "AIS_ERRORS_ENDPOINT" => Some("https://errors.example.org".to_owned()),
                "AIS_ERRORS_INGEST_TOKEN" => Some("short".to_owned()),
                _ => None,
            }),
            Err(SetupError::Token)
        ));
    }

    #[test]
    fn event_is_errors_v1_without_sensitive_request_fields() {
        let event = ErrorEvent::new(
            "identity.runtime.failure",
            "4x-ais.runtime",
            "AIS logged an internal error",
            serde_json::json!({"target": "ais::issuer"}),
        )
        .unwrap();
        let serialized = serde_json::to_value(event).unwrap();
        assert_eq!(serialized["protocol_version"], "errors.v1");
        assert_eq!(serialized["project"], PROJECT);
        assert_eq!(serialized["severity"], "error");
        assert_eq!(serialized["event_id"].as_str().unwrap().len(), 36);
        assert_eq!(serialized["event_id"].as_str().unwrap().chars().nth(14), Some('4'));
        assert!(chrono::DateTime::parse_from_rfc3339(
            serialized["observed_at"].as_str().unwrap()
        ).is_ok());
        assert_eq!(serialized["context"]["target"], "ais::issuer");
        assert!(serialized.get("authorization").is_none());
        assert!(serialized.get("request").is_none());
    }

    #[tokio::test]
    async fn collector_receives_project_bound_event_without_blocking_host() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = oneshot::channel::<(String, Value)>();
        let sender = Arc::new(Mutex::new(Some(sender)));
        let app = Router::new().route(
            "/v1/events",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let sender = sender.clone();
                async move {
                    let auth = headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    if let Some(sender) = sender.lock().unwrap().take() {
                        let _ = sender.send((auth, body));
                    }
                    StatusCode::CREATED
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // HTTP is used only inside this loopback test; production parsing
        // requires HTTPS and never accepts a non-origin endpoint.
        let mut authorization = HeaderValue::from_static(
            "Bearer tttttttttttttttttttttttttttttttttttttttttttttttt",
        );
        authorization.set_sensitive(true);
        let reporter = Reporter::start(ReporterConfig {
            endpoint: Url::parse(&format!("http://{address}/v1/events")).unwrap(),
            authorization,
        })
        .unwrap();
        reporter.report_http(503, "/token");
        let (auth, event) = tokio::time::timeout(Duration::from_secs(3), receiver)
            .await
            .unwrap()
            .unwrap();
        assert!(auth.starts_with("Bearer tttt"));
        assert_eq!(event["project"], PROJECT);
        assert_eq!(event["context"]["status"], 503);
        assert_eq!(event["context"]["route"], "/token");
        assert!(event.get("user").is_none());
        server.abort();
    }
}
