#![allow(unused)]
use std::{env::var, fs::read_to_string, net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use dotenvy::from_filename;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic_reflection::server::Builder;
use tracing_subscriber::{EnvFilter, fmt};
#[macro_use]
extern crate tracing;

use crate::auth::{AuthServer, FILE_DESCRIPTOR_SET, auth_service_server::AuthServiceServer};

mod auth;

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    from_filename(env_path).context("Failed to load .env file")?;

    fmt()
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cert_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("certs");
    if !cert_path.exists() {
        return Err(anyhow::anyhow!("Certs directory does not exist"));
    }

    let cert =
        read_to_string(cert_path.join("auth-server.crt")).context("Failed to read certificate")?;
    let key = read_to_string(cert_path.join("auth-server.key")).context("Failed to read key")?;
    let identity = Identity::from_pem(cert, key);

    let addr = var("ADDRESS")
        .context("ADDRESS not set")?
        .parse::<SocketAddr>()
        .context("ADDRESS is not in a proper format")?;

    info!("Starting server on {addr:?}");
    let server = AuthServer;
    let reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
        .context("Failed to build reflection service")?;

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))
        .context("Failed to configure TLS")?
        .add_service(AuthServiceServer::new(server))
        .add_service(reflection_service)
        .serve(addr)
        .await
        .context("Failed to start server")
}
