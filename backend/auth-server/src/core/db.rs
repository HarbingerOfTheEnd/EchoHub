use sea_orm::{ActiveValue::Set, DeleteResult, prelude::*};

use super::entities::user;

pub(crate) struct Query;
pub(crate) struct Mutation;

impl Query {
    pub async fn get_user_by_username(
        db: &DbConn,
        username: &str,
    ) -> Result<Option<user::Model>, DbErr> {
        user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(db)
            .await
    }

    pub async fn get_user_by_email(db: &DbConn, email: &str) -> Result<Option<user::Model>, DbErr> {
        user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(db)
            .await
    }
}

impl Mutation {
    pub async fn create_user(
        db: &DbConn,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<user::Model, DbErr> {
        let user = user::ActiveModel {
            username: Set(username.to_string()),
            email: Set(email.to_string()),
            password: Set(password.to_string()),
            ..Default::default()
        };

        user.insert(db).await
    }

    pub async fn update_user(db: &DbConn, user: user::ActiveModel) -> Result<user::Model, DbErr> {
        user.update(db).await
    }

    pub async fn delete_user(db: &DbConn, user_id: u64) -> Result<DeleteResult, DbErr> {
        let user = user::Entity::find_by_id(user_id).one(db).await?;
        if let Some(user) = user {
            user.delete(db).await
        } else {
            Err(DbErr::RecordNotFound(format!(
                "User with id {} not found",
                user_id
            )))
        }
    }
}
