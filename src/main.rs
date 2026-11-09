// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

use ais::{config::Config, router, store::Store};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // A missing or unsafe setting stops the service before it listens.
    let config = Config::from_lookup(|key| std::env::var(key).ok())
        .unwrap_or_else(|error| panic!("{error}"));
    let store = Store::connect(&config.database_url)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let bind = config.bind;
    info!(issuer = %config.issuer_id(), clients = config.clients.len(), "aiaiaiai AIS starting");
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .unwrap_or_else(|error| panic!("cannot bind {bind}: {error}"));
    axum::serve(listener, router(config, store))
        .with_graceful_shutdown(shutdown())
        .await
        .expect("the HTTP server stopped unexpectedly");
}

/// `docker stop` sends SIGTERM; a terminal sends SIGINT. Either drains and stops.
async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
