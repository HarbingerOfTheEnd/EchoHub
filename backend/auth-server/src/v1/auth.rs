use std::sync::Arc;

use auth_service_server::AuthService;
use bcrypt::{DEFAULT_COST, hash, verify};
use sea_orm::{
    DatabaseConnection,
    DbErr::{Query as QueryErr, RecordNotFound},
    RuntimeErr::SqlxError,
    TransactionTrait, error,
    sqlx::Error::Database,
};
use serde_json::Value;
use tonic::{Request, Response, Status, async_trait, include_file_descriptor_set, include_proto};

use crate::{
    core::{
        db::{Mutation, Query},
        enums::scope::Scope,
        util::{
            ACCESS_TOKEN_EXPIRES_IN, generate_jwt_token, generate_token_pair, parse_jwt_token,
            send_email,
        },
    },
    map,
};

include_proto!("v1.auth");

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

        info!("Received signup request: username={username}, email={email}");

        let hashed_password = hash(password, DEFAULT_COST)
            .map_err(|_| Status::internal("Failed to hash password"))?;

        let txn = self.db.begin().await.map_err(|_| {
            error!("Failed to begin transaction");
            Status::internal("Failed to begin transaction")
        })?;

        let user = match Mutation::create_user(&txn, &username, &email, &hashed_password).await {
            Ok(user) => {
                info!("User created successfully: {:?}", user.id);
                user
            }
            Err(QueryErr(SqlxError(Database(error)))) => {
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

        let (access_token, refresh_token) = generate_token_pair(&user.id);

        match Mutation::create_oauth2_token_pair(
            &txn,
            &user.id,
            &access_token,
            &refresh_token,
            "USER",
            Scope::USER,
        )
        .await
        {
            Err(QueryErr(SqlxError(Database(error)))) => {
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
                        error!("Database error: {:?}", error.message());
                    }
                }
                return Err(Status::invalid_argument("Failed to create token pair"));
            }
            _ => {
                info!("Token pair created successfully");
            }
        }

        let jwt = generate_jwt_token(map! {
            "user_id" => user.id,
            "exp" => 600,
        })
        .map_err(|e| {
            error!("Failed to generate JWT token: {e:?}");
            Status::internal("Failed to generate JWT token")
        })?;
        #[cfg(not(test))]
        {
            let send_email_future = send_email(
                &email,
                "Welcome to EchoHub!",
                format!(
                    r#"
                    <html>
                        <body>
                            <h1>Welcome to EchoHub!</h1>
                            <p>Thank you for signing up. Please verify your email address.</p>
                            <a href="https://auth-server.local:8000/v1/verify-email?token={jwt}">Verify Email</a>
                        </body>
                    </html>
                "#
                ),
            );

            match send_email_future.await {
                Ok(()) => {
                    info!("Email sent successfully to {email}");
                }
                Err(e) => {
                    error!("Failed to send email: {e:?}");
                    return Err(Status::internal("Failed to send email"));
                }
            }
        }

        match txn.commit().await {
            Ok(_) => {
                info!("Transaction committed successfully");
            }
            Err(e) => {
                error!("Failed to commit transaction: {e:?}");
                return Err(Status::internal("Failed to commit transaction"));
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
        request: Request<SigninRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        let SigninRequest { email, password } = request.into_inner();
        if email.is_empty() || password.is_empty() {
            return Err(Status::invalid_argument("All fields are required"));
        }

        info!("Received signin request: email={email}");

        let txn = self.db.begin().await.map_err(|_| {
            error!("Failed to begin transaction");
            Status::internal("Failed to begin transaction")
        })?;
        let user = match Query::get_user_by_email(&txn, &email).await {
            Ok(Some(user)) => {
                info!("User found: {:?}", user.id);
                user
            }
            Ok(None) => {
                error!("User not found");
                return Err(Status::not_found("User not found"));
            }
            Err(QueryErr(SqlxError(Database(error)))) => {
                match error.constraint() {
                    Some("users_email_key") => {
                        error!("Email not found: {error:?}");
                        return Err(Status::not_found("Email not found"));
                    }
                    _ => {
                        error!("Database error: {error:?}");
                    }
                }
                return Err(Status::invalid_argument("Failed to find user"));
            }
            Err(err) => {
                error!("Failed to find user: {err:?}");
                return Err(Status::internal("Failed to find user"));
            }
        };
        let verified = verify(&password, &user.password)
            .map_err(|_| Status::internal("Failed to verify password"))?;

        if !verified {
            error!("Invalid password");
            return Err(Status::unauthenticated("Invalid password"));
        }

        let (access_token, refresh_token) = generate_token_pair(&user.id);
        match Mutation::create_oauth2_token_pair(
            &txn,
            &user.id,
            &access_token,
            &refresh_token,
            "USER",
            Scope::USER,
        )
        .await
        {
            Err(QueryErr(SqlxError(Database(error)))) => {
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
                        error!("Database error: {:?}", error.message());
                    }
                }
                return Err(Status::invalid_argument("Failed to create token pair"));
            }
            _ => {
                info!("Token pair created successfully");
            }
        }

        match txn.commit().await {
            Ok(_) => {
                info!("Transaction committed successfully");
            }
            Err(e) => {
                error!("Failed to commit transaction: {e:?}");
                return Err(Status::internal("Failed to commit transaction"));
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
    async fn verify_email(
        &self,
        request: Request<VerifyEmailRequest>,
    ) -> Result<Response<VerifyEmailResponse>, Status> {
        let VerifyEmailRequest { token } = request.into_inner();
        if token.is_empty() {
            return Err(Status::invalid_argument("Token is required"));
        }

        let token =
            parse_jwt_token(&token).map_err(|_| Status::invalid_argument("Invalid token"))?;
        let user_id = token
            .get("user_id")
            .unwrap_or(&Value::String("".to_string()))
            .as_str()
            .unwrap_or_default()
            .to_string();

        let txn = self.db.begin().await.map_err(|_| {
            error!("Failed to begin transaction");
            Status::internal("Failed to begin transaction")
        })?;

        match Mutation::verify_email(&txn, &user_id).await {
            Ok(_) => {
                info!("Email verified successfully");
            }
            Err(RecordNotFound(e)) => {
                error!("Record not found: {e:?}");
                return Err(Status::not_found("User not found"));
            }
            Err(e) => {
                error!("Failed to verify email: {e:?}");
                return Err(Status::internal("Failed to verify email"));
            }
        }

        match txn.commit().await {
            Ok(_) => {
                info!("Transaction committed successfully");
            }
            Err(e) => {
                error!("Failed to commit transaction: {e:?}");
                return Err(Status::internal("Failed to commit transaction"));
            }
        }

        Ok(Response::new(VerifyEmailResponse::default()))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, MockDatabase, MockExecResult, TransactionTrait};
    use serial_test::serial;
    use std::{env::set_var, sync::Once};
    use time::OffsetDateTime;
    use tonic::{
        Code::{InvalidArgument, NotFound},
        Request,
    };

    use super::*;

    fn setup_env() {
        unsafe {
            set_var("EH_WORKER_ID", "1");
            set_var("EH_PROCESS_ID", "2");
            set_var("EH_EMAIL", "test@example.com");
            set_var("EH_SMTP_SERVER", "smtp.example.com");
            set_var("EH_SMTP_PORT", "587");
            set_var("EH_EMAIL_PASSWORD", "password");
            set_var("EH_JWT_SECRET", "supersecretkey");
        };
    }

    fn mock_db_signup() -> DatabaseConnection {
        MockDatabase::new(DbBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![entity::users::Model {
                id: "1".to_string(),
                username: "testuser".to_string(),
                email: "test@example.com".to_string(),
                password: "hashedpassword".to_string(),
                discriminator: 1000,
                email_verified: false,
                created_at: OffsetDateTime::now_utc(),
            }]])
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![entity::oauth2_token_pairs::Model {
                id: "1".to_string(),
                user_id: "1".to_string(),
                access_token: "access".to_string(),
                refresh_token: "refresh".to_string(),
                r#type: "USER".to_string(),
                access_token_expires_at: OffsetDateTime::now_utc(),
                refresh_token_expires_at: OffsetDateTime::now_utc(),
                scope: 1,
            }]])
            .into_connection()
    }

    fn mock_db() -> DatabaseConnection {
        MockDatabase::new(DbBackend::Postgres).into_connection()
    }

    fn mock_db_signin_not_found() -> DatabaseConnection {
        MockDatabase::new(DbBackend::Postgres)
            .append_query_results(vec![Vec::<entity::users::Model>::new()])
            .into_connection()
    }

    #[tokio::test]
    #[serial]
    async fn test_signup_success() {
        setup_env();
        let db = mock_db_signup();
        let server = AuthServer::new(db);
        let req = SignupRequest {
            username: "testuser".into(),
            password: "testpass123".into(),
            email: "test@example.com".into(),
        };
        let resp = server.signup(Request::new(req)).await;
        assert!(resp.is_ok());
        let token_resp = resp.unwrap().into_inner();
        assert!(!token_resp.access_token.is_empty());
        assert!(!token_resp.refresh_token.is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_signup_missing_fields() {
        setup_env();
        let db = mock_db();
        let server = AuthServer::new(db);
        let req = SignupRequest {
            username: "".into(),
            password: "".into(),
            email: "".into(),
        };
        let resp = server.signup(Request::new(req)).await;
        assert!(resp.is_err());
        let status = resp.err().unwrap();
        assert_eq!(status.code(), InvalidArgument);
    }

    #[tokio::test]
    #[serial]
    async fn test_signin_invalid_user() {
        setup_env();
        let db = mock_db_signin_not_found();
        let server = AuthServer::new(db);
        let req = SigninRequest {
            email: "nouser@example.com".into(),
            password: "wrongpass".into(),
        };
        let resp = server.signin(Request::new(req)).await;
        assert!(resp.is_err());
        let status = resp.err().unwrap();
        assert_eq!(status.code(), NotFound);
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_email_invalid_token() {
        setup_env();
        let db = mock_db();
        let server = AuthServer::new(db);
        let req = VerifyEmailRequest {
            token: "invalidtoken".into(),
        };
        let resp = server.verify_email(Request::new(req)).await;
        assert!(resp.is_err());
        let status = resp.err().unwrap();
        assert_eq!(status.code(), InvalidArgument);
    }
}
