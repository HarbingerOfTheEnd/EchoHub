use entity::user;
use sea_orm::{ActiveValue::Set, DeleteResult, prelude::*};
use time::OffsetDateTime;

use crate::core::util::generate_snowflake;

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
        let now = (OffsetDateTime::now_utc().unix_timestamp() * 1_000) as u64;
        let new_user = user::ActiveModel {
            id: Set(generate_snowflake(now)),
            username: Set(username.to_string()),
            email: Set(email.to_string()),
            password: Set(password.to_string()),
            ..Default::default()
        };

        new_user.insert(db).await
    }

    pub async fn update_user(db: &DbConn, user: user::Model) -> Result<user::Model, DbErr> {
        let user = user::ActiveModel::from(user);

        user.update(db).await
    }

    pub async fn delete_user(db: &DbConn, user_id: &str) -> Result<DeleteResult, DbErr> {
        user::Entity::delete_by_id(user_id).exec(db).await
    }
}
