use anyhow::Result;
use sea_orm::{ActiveValue::Set, DeleteResult, prelude::*};

pub(crate) struct Query;
pub(crate) struct Mutation;

impl Query {
    pub async fn get_user_by_username(db: &DbConn, username: &str) -> Result<Option<()>> {
        todo!()
    }

    pub async fn get_user_by_email(db: &DbConn, email: &str) -> Result<Option<()>> {
        todo!()
    }
}

impl Mutation {
    pub async fn create_user(
        db: &DbConn,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<()> {
        todo!()
    }

    pub async fn update_user(db: &DbConn, user: Option<()>) -> Result<()> {
        todo!()
    }

    pub async fn delete_user(db: &DbConn, user_id: u64) -> Result<DeleteResult, DbErr> {
        todo!()
    }
}
