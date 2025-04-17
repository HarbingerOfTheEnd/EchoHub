use std::sync::Arc;

use auth_service_server::AuthService;
use sea_orm::DatabaseConnection;
use tonic::{Request, Response, Status, async_trait, include_file_descriptor_set, include_proto};

include_proto!("auth");

pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = include_file_descriptor_set!("auth_descriptor");

#[derive(Debug)]
pub struct AuthServer {
    db: Arc<DatabaseConnection>,
}

impl AuthServer {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db: Arc::new(db) }
    }
}

#[async_trait]
impl AuthService for AuthServer {
    #[instrument]
    async fn signup(
        &self,
        request: Request<SignupRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        info!("Received signup request");
        Ok(Response::new(TokenResponse::default()))
    }

    #[instrument]
    async fn signin(
        &self,
        _request: Request<SigninRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        info!("Received signin request");
        Ok(Response::new(TokenResponse::default()))
    }
}
