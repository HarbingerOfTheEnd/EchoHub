use std::{env::var, net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use auth_service_client::AuthServiceClient;
use tokio::fs::read_to_string;
use tonic::{
    include_proto,
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
};

include_proto!("v1.auth");

#[derive(Clone, Debug)]
pub(crate) struct GrpcClient {
    pub(crate) auth_client: AuthServiceClient<Channel>,
}

impl GrpcClient {
    pub(crate) async fn new() -> Result<Self> {
        let ca_cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("ca")
            .join("certs")
            .join("ca.crt");
        let client_cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client.crt");
        let client_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client.key");

        let ca_cert = read_to_string(ca_cert_path)
            .await
            .context("Failed to read CA certificate")?;
        let client_cert = read_to_string(client_cert_path)
            .await
            .context("Failed to read client certificate")?;
        let client_key = read_to_string(client_key_path)
            .await
            .context("Failed to read client key")?;

        let ca = Certificate::from_pem(ca_cert);
        let identity = Identity::from_pem(client_cert, client_key);

        let tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);

        let auth_server_address = var("AUTH_SERVER_ADDRESS")
            .context("AUTH_SERVER_ADDRESS not set")?
            .parse::<SocketAddr>()
            .context("Failed to parse AUTH_SERVER_ADDRESS")?;

        let channel = Channel::from_shared(format!("https://{}", auth_server_address))
            .context("Failed to create channel")?
            .tls_config(tls)
            .context("Failed to configure TLS")?
            .connect()
            .await
            .context("Failed to connect to gRPC server")?;

        let auth_client = AuthServiceClient::new(channel);
        Ok(Self { auth_client })
    }
}
