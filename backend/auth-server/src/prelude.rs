use std::{env::var, sync::Arc};

use axum::{routing::get, Router};
use sea_orm::{Database, DbConn};

use crate::api::v1::oauth2::authorize;

#[cfg(not(test))]
pub async fn get_db_conn() -> Arc<DbConn> {
    let db_url = var("DATABASE_URL").expect("DATABASE_URL is not set");

    Arc::new(Database::connect(&db_url).await.unwrap())
}

#[cfg(test)]
pub async fn get_db_conn() -> Arc<DbConn> {
    let db = sea_orm::MockDatabase::new(sea_orm::DatabaseBackend::Postgres);

    Arc::new(db.into_connection())
}

fn oauth_router(db: Arc<DbConn>) -> Router {
    Router::new()
        .route("/authorize", get(authorize))
        .with_state(db.clone())
}

fn v1_router(db: Arc<DbConn>) -> Router {
    Router::new().nest("/oauth", oauth_router(db.clone()))
}

pub fn app(db: Arc<DbConn>) -> Router {
    Router::new().nest("/api/v1", v1_router(db.clone()))
}
