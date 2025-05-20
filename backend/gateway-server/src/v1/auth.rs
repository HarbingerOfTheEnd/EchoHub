use std::env::var;

use anyhow::{Context, Result};
use auth_service_client::AuthServiceClient;
use tonic::{include_proto, transport::Channel};

include_proto!("v1.auth");

#[derive(Clone, Debug)]
pub(crate) struct GrpcClients {
    pub(crate) auth_client: AuthServiceClient<Channel>,
}

impl GrpcClients {
    pub(crate) async fn new() -> Result<Self> {
        let auth_service_url = var("AUTH_SERVICE_URL").context("AUTH_SERVICE_URL not set")?;
        let auth_client = AuthServiceClient::connect(auth_service_url)
            .await
            .context("Failed to connect to auth service")?;

        Ok(Self { auth_client })
    }
}
