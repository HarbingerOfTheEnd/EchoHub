use async_graphql::{Context, FieldError, Object, Result};

use crate::{
    GrpcClient,
    v1::client::{SigninRequest, SignupRequest, TokenResponse, VerifyEmailRequest},
};

#[derive(Default)]
pub(crate) struct AuthMutation;

#[Object]
impl AuthMutation {
    async fn signup(&self, ctx: &Context<'_>, request: SignupRequest) -> Result<TokenResponse> {
        info!("Recieved sign up request");
        let mut auth_service_client = ctx.data_unchecked::<GrpcClient>().auth_client.clone();
        let request = SignupRequest { ..request.into() };

        info!("Sending sign up request to auth service");
        let response = auth_service_client.signup(request).await;

        match response {
            Ok(response) => {
                info!("Received OK response from auth service");
                Ok(response.into_inner().into())
            }
            Err(err) => {
                error!("Error from auth service: {err:?}");
                Err(FieldError::new(err.message()))
            }
        }
    }

    async fn signin(&self, ctx: &Context<'_>, request: SigninRequest) -> Result<TokenResponse> {
        info!("Recieved sign in request");
        let mut auth_service_client = ctx.data_unchecked::<GrpcClient>().auth_client.clone();
        let request = SigninRequest { ..request.into() };

        info!("Sending sign in request to auth service");
        let response = auth_service_client.signin(request).await;

        match response {
            Ok(response) => {
                info!("Received OK response from auth service");
                Ok(response.into_inner().into())
            }
            Err(err) => {
                error!("Error from auth service: {err:?}");
                Err(FieldError::new(err.message()))
            }
        }
    }

    async fn verify_email(&self, ctx: &Context<'_>, request: VerifyEmailRequest) -> Result<bool> {
        info!("Recieved verify email request");
        let mut auth_service_client = ctx.data_unchecked::<GrpcClient>().auth_client.clone();
        let request = VerifyEmailRequest { ..request.into() };

        info!("Sending verify email request to auth service");
        let response = auth_service_client.verify_email(request).await;

        match response {
            Ok(_) => {
                info!("Received OK response from auth service");
                Ok(true)
            }
            Err(err) => {
                error!("Error from auth service: {err:?}");
                Err(FieldError::new(err.message()))
            }
        }
    }
}
