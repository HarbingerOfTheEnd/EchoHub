use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use sea_orm::DbConn;

use crate::requests::auth::SignupRequest;

#[instrument]
pub async fn signup(
    State(db): State<Arc<DbConn>>,
    Json(body): Json<SignupRequest>,
) -> impl IntoResponse {
    if body.email.is_empty() || body.username.is_empty() || body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "Invalid request").into_response();
    }
    Json(vec![] as Vec<String>).into_response()
}

#[instrument]
pub async fn signin(State(_db): State<Arc<DbConn>>) -> impl IntoResponse {
    "signup".into_response()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use axum::{body::Body, extract::Request};
    use dotenvy::from_path;
    use hyper::{header::CONTENT_TYPE, Method, StatusCode};
    use mime::APPLICATION_JSON;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::{prelude::*, requests::auth::SignupRequest};

    #[tokio::test]
    async fn test_signup() {
        from_path(Path::new(env!("CARGO_MANIFEST_DIR")).join(".env")).unwrap();
        init_tracing();
        let db = get_mock_db_conn().await;
        let app = app(db);

        let body = SignupRequest {
            email: String::from("example@email.com"),
            username: String::from("HarbingerOfTheEnd"),
            password: {
                let mut hasher = Sha256::new();
                hasher.update("password");

                format!("{:x}", hasher.finalize())
            },
        };
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/signup")
            .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
