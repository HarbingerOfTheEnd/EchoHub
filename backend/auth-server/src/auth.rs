use auth_service_server::AuthService;
use tonic::{Request, Response, async_trait, include_proto};

include_proto!("auth");

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
