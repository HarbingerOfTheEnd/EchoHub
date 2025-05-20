#![allow(unused)]
use std::{
    env::var,
    fs::{read, read_to_string},
    net::SocketAddr,
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use dotenvy::from_filename;
use migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectOptions, Database};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic_reflection::server::Builder;
use tracing::{Level, log::LevelFilter::Debug};
use tracing_subscriber::{EnvFilter, fmt};
#[macro_use]
extern crate tracing;

use crate::v1::auth::{AuthServer, FILE_DESCRIPTOR_SET, auth_service_server::AuthServiceServer};

mod core;
mod v1;

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    from_filename(env_path).context("Failed to load .env file")?;

    fmt()
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cert_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("certs");
    let ca_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("ca");
    if !cert_path.exists() || !cert_path.exists() {
        return Err(anyhow!("Certs directory does not exist"));
    }

    let cert = read_to_string(cert_path.join("auth-server.local.crt"))
        .context("Failed to read certificate")?;
    let key =
        read_to_string(cert_path.join("auth-server.local.key")).context("Failed to read key")?;
    let identity = Identity::from_pem(cert, key);
    let client_ca_root =
        read_to_string(ca_path.join("certs").join("ca.crt")).context("Failed to read ca cert")?;
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_auth_optional(false)
        .client_ca_root(Certificate::from_pem(client_ca_root));

    let addr = var("ADDRESS")
        .context("ADDRESS not set")?
        .parse::<SocketAddr>()
        .context("ADDRESS is not in a proper format")?;

    info!("Connecting to PostgreSQL");
    let postgres_url = var("DATABASE_URL").context("DATABASE_URL not set")?;
    let mut connect_options = ConnectOptions::new(&postgres_url);
    connect_options
        .max_connections(5)
        .min_connections(1)
        .idle_timeout(std::time::Duration::from_secs(30))
        .sqlx_logging(false)
        .sqlx_logging_level(Debug);
    let db = Database::connect(connect_options)
        .await
        .context("Failed to connect to database")?;
    info!("Connected to PostgreSQL server");

    info!("Applying migrations");
    Migrator::up(&db, None)
        .await
        .context("Failed to apply migrations")?;

    info!("Starting server on {addr:?}");
    let server = AuthServer::new(db);
    let reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1alpha()
        .context("Failed to build reflection service")?;

    Server::builder()
        .tls_config(tls)
        .context("Failed to configure TLS")?
        .add_service(AuthServiceServer::new(server))
        .add_service(reflection_service)
        .serve(addr)
        .await
        .context("Failed to start server")
}
