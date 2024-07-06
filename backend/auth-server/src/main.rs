pub(crate) mod api;
pub(crate) mod prelude;

use std::{env::var, net::SocketAddr, path::Path};

use axum::serve;
use dotenvy::from_path;
use tokio::net::TcpListener;
#[macro_use]
extern crate tracing;
use crate::prelude::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_env("RUST_LOG"))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();
}

#[tokio::main]
async fn main() {
    let envfile = Path::new("")
        .join("backend")
        .join("auth-server")
        .join(".env");

    if let Ok(()) = from_path(&envfile) {
        init_tracing();
        info!("Loaded .env file from path: {envfile:?}");
    } else {
        panic!("Failed to load .env file");
    }

    let db_conn = get_db_conn().await;
    info!("Connected to database");

    let address = var("ADDRESS")
        .expect("ADDRESS must be set")
        .parse::<SocketAddr>()
        .unwrap();
    let listener = TcpListener::bind(&address).await.unwrap();
    info!("Listening on: {address:?}");

    serve(listener, app(db_conn.clone())).await.unwrap();
}
