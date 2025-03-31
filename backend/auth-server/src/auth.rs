use auth_service_server::AuthService;
use tonic::{Request, Response, async_trait, include_file_descriptor_set, include_proto};

include_proto!("auth");

pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = include_file_descriptor_set!("auth_descriptor");

#[derive(Debug)]
pub struct AuthServer;

#[async_trait]
impl AuthService for AuthServer {
    #[instrument]
    async fn signup(
        &self,
        _request: Request<SignupRequest>,
    ) -> Result<Response<TokenResponse>, tonic::Status> {
        info!("Received signup request");
        Ok(Response::new(TokenResponse::default()))
    }

    #[instrument]
    async fn signin(
        &self,
        _request: Request<SigninRequest>,
    ) -> Result<Response<TokenResponse>, tonic::Status> {
        info!("Received signin request");
        Ok(Response::new(TokenResponse::default()))
    }
}
