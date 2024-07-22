use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};
use sea_orm::DbConn;

pub fn authorize(State(_db): State<Arc<DbConn>>) -> impl IntoResponse {
    "Authorize"
}
