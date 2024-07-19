use std::{env::var, sync::Arc};

use axum::{routing::post, Router};
#[cfg(test)]
use sea_orm::MockDatabase;
use sea_orm::{Database, DbConn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::api::v1::oauth2::authorize;

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_env("RUST_LOG"))
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();
}

pub async fn get_db_conn() -> Arc<DbConn> {
    let db_url = var("DATABASE_URL").expect("DATABASE_URL is not set");

    Arc::new(Database::connect(&db_url).await.unwrap())
}

#[cfg(test)]
pub async fn get_mock_db_conn() -> Arc<DbConn> {
    let db = MockDatabase::new(sea_orm::DatabaseBackend::Postgres);

    Arc::new(db.into_connection())
}

fn oauth_router(db: Arc<DbConn>) -> Router {
    Router::new()
        .route("/authorize", post(authorize))
        .with_state(db)
}

fn v1_router(db: Arc<DbConn>) -> Router {
    Router::new().nest("/oauth2", oauth_router(db))
}

pub fn app(db: Arc<DbConn>) -> Router {
    Router::new().nest("/api/v1", v1_router(db))
}
