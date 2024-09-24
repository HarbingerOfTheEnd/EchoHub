mod api;
mod prelude;
mod requests;
mod responses;

#[cfg(not(unix))]
use std::future::pending;
use std::{env::var, path::Path};

use axum::serve;
use dotenvy::from_path;
use sentry::{release_name, ClientOptions};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::{net::TcpListener, select, signal::ctrl_c};

use crate::prelude::*;

#[macro_use]
extern crate tracing;

async fn shutdown_signal() {
    let ctrl_c = async {
        ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = pending::<()>();

    select! {
        () = ctrl_c => info!("Received CTRL+C signal"),
        () = terminate => info!("Received SIGTERM signal"),

    }
}

#[tokio::main]
async fn main() {
    let cwd = env!("CARGO_MANIFEST_DIR");
    let envfile = Path::new(cwd).join(".env");

    if let Ok(()) = from_path(&envfile) {
        init_tracing();
        info!("Loaded .env file from path: {envfile:?}");
    } else {
        panic!("Failed to load .env file");
    }

    let dsn = var("SENTRY_DSN").expect("SENTRY_DSN must be set");
    let _guard = sentry::init((
        dsn,
        ClientOptions {
            release: release_name!(),
            ..Default::default()
        },
    ));

    let db_conn = get_db_conn().await;
    info!("Connected to database");

    let address = var("ADDRESS").expect("ADDRESS must be set");
    let listener = TcpListener::bind(&address).await.unwrap();
    info!("Listening on: http://{address}");

    serve(listener, app(db_conn))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}
