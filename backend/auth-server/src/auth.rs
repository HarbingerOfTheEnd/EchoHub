use std::sync::Arc;

use auth_service_server::AuthService;
use bcrypt::{DEFAULT_COST, hash};
use sea_orm::{
    DatabaseConnection, DbErr::Query, RuntimeErr::SqlxError, error, sqlx::Error::Database,
};
use tonic::{Request, Response, Status, async_trait, include_file_descriptor_set, include_proto};

use crate::core::{
    db::Mutation,
    util::{ACCESS_TOKEN_EXPIRES_IN, generate_token_pair},
};

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
    #[instrument(skip_all)]
    async fn signup(
        &self,
        request: Request<SignupRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        let SignupRequest {
            username,
            password,
            email,
        } = request.into_inner();

        if username.is_empty() || password.is_empty() || email.is_empty() {
            return Err(Status::invalid_argument("All fields are required"));
        }

        info!(
            "Received signup request: username={}, email={}",
            username, email
        );

        let hashed_password = hash(password, DEFAULT_COST)
            .map_err(|_| Status::internal("Failed to hash password"))?;

        let user = match Mutation::create_user(&self.db, &username, &email, &hashed_password).await
        {
            Ok(user) => {
                info!("User created successfully: {:?}", user.id);
                user
            }
            Err(Query(SqlxError(Database(error)))) => {
                match error.constraint() {
                    Some("users_username_key") => {
                        error!("Username already exists: {error:?}");
                        return Err(Status::already_exists("Username already exists"));
                    }
                    Some("users_email_key") => {
                        error!("Email already exists: {error:?}");
                        return Err(Status::already_exists("Email already exists"));
                    }
                    _ => {
                        error!("Database error: {error:?}");
                    }
                }
                return Err(Status::invalid_argument("Failed to create user due"));
            }
            Err(err) => {
                error!("Failed to create user: {err:?}");
                return Err(Status::internal("Failed to create user"));
            }
        };

        info!("User created successfully: {:?}", user.id);
        let (access_token, refresh_token) = generate_token_pair(&user.id);

        match Mutation::create_oauth2_token_pair(&self.db, &user.id, &access_token, &refresh_token)
            .await
        {
            Err(Query(SqlxError(Database(error)))) => {
                match error.constraint() {
                    Some("oauth2_token_pairs_user_id_fkey") => {
                        error!("User not found: {error:?}");
                        return Err(Status::not_found("User not found"));
                    }
                    Some("oauth2_token_pairs_access_token_key") => {
                        error!("Access token already exists: {error:?}");
                        return Err(Status::already_exists("Access token already exists"));
                    }
                    Some("oauth2_token_pairs_refresh_token_key") => {
                        error!("Refresh token already exists: {error:?}");
                        return Err(Status::already_exists("Refresh token already exists"));
                    }
                    _ => {
                        error!("Database error: {error:?}");
                    }
                }
                return Err(Status::invalid_argument("Failed to create token pair"));
            }
            _ => {
                info!("Token pair created successfully");
            }
        }

        let response = TokenResponse {
            access_token,
            refresh_token,
            token_type: String::from("Bearer"),
            expires_in: ACCESS_TOKEN_EXPIRES_IN,
            scope: vec![String::from("USER")],
        };

        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn signin(
        &self,
        _request: Request<SigninRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        info!("Received signin request");
        Ok(Response::new(TokenResponse::default()))
    }
}
