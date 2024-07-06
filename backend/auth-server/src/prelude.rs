use axum::{routing::get, Router};

use crate::api::v1::oauth2::authorize;

fn oauth_router() -> Router {
    Router::new().route("/authorize", get(authorize))
}

fn v1_router() -> Router {
    Router::new().nest("/oauth", oauth_router())
}

pub fn app() -> Router {
    Router::new().nest("/api/v1", v1_router())
}
