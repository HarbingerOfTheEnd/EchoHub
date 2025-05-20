use async_graphql::{Context, InputObject, Object, Result, SimpleObject};

use crate::{
    GrpcClient,
    v1::client::{SignupRequest, TokenResponse},
};

#[derive(Default)]
pub(crate) struct AuthMutation;

#[derive(InputObject)]
struct GQLSignupRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl Into<SignupRequest> for GQLSignupRequest {
    fn into(self) -> SignupRequest {
        SignupRequest {
            username: self.username,
            email: self.email,
            password: self.password,
        }
    }
}

#[derive(SimpleObject)]
struct GQLTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Vec<String>,
}

impl Into<GQLTokenResponse> for TokenResponse {
    fn into(self) -> GQLTokenResponse {
        GQLTokenResponse {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            token_type: self.token_type,
            expires_in: self.expires_in,
            scope: self.scope,
        }
    }
}

#[Object]
impl AuthMutation {
    async fn signup(
        &self,
        ctx: &Context<'_>,
        request: GQLSignupRequest,
    ) -> Result<GQLTokenResponse> {
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
                Err(err.into())
            }
        }
    }
}
