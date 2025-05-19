use entity::{oauth2_token_pairs, users};
use rand::random_range;
use sea_orm::{ActiveValue::Set, DeleteResult, prelude::*};
use time::{Duration, OffsetDateTime};

use crate::core::util::generate_snowflake;

use super::{
    enums::scope::Scope,
    util::{ACCESS_TOKEN_EXPIRES_IN, REFRESH_TOKEN_EXPIRES_IN},
};

pub(crate) struct Query;
pub(crate) struct Mutation;

impl Query {
    pub async fn get_user_by_username(
        db: &DbConn,
        username: &str,
    ) -> Result<Option<users::Model>, DbErr> {
        users::Entity::find()
            .filter(users::Column::Username.eq(username))
            .one(db)
            .await
    }

    pub async fn get_user_by_email(
        db: &DbConn,
        email: &str,
    ) -> Result<Option<users::Model>, DbErr> {
        users::Entity::find()
            .filter(users::Column::Email.eq(email))
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
    ) -> Result<users::Model, DbErr> {
        let now = (OffsetDateTime::now_utc().unix_timestamp() * 1_000) as u64;
        let discriminator = random_range(1000..=9999);
        let new_user = users::ActiveModel {
            id: Set(generate_snowflake(now)),
            username: Set(username.to_string()),
            email: Set(email.to_string()),
            password: Set(password.to_string()),
            discriminator: Set(discriminator),
            ..Default::default()
        };

        new_user.insert(db).await
    }

    pub async fn update_user(db: &DbConn, user: users::Model) -> Result<users::Model, DbErr> {
        let user = users::ActiveModel::from(user);

        user.update(db).await
    }

    pub async fn delete_user(db: &DbConn, user_id: &str) -> Result<DeleteResult, DbErr> {
        users::Entity::delete_by_id(user_id).exec(db).await
    }

    pub async fn create_oauth2_token_pair(
        db: &DbConn,
        user_id: &str,
        access_token: &str,
        refresh_token: &str,
        r#type: &str,
        scope: i64,
    ) -> Result<oauth2_token_pairs::Model, DbErr> {
        let now = OffsetDateTime::now_utc();
        let new_token_pair = oauth2_token_pairs::ActiveModel {
            id: Set(generate_snowflake((now.unix_timestamp() * 1_000) as u64)),
            user_id: Set(user_id.to_string()),
            access_token: Set(access_token.to_string()),
            refresh_token: Set(refresh_token.to_string()),
            r#type: Set(r#type.to_string()),
            access_token_expires_at: Set(now + Duration::seconds(ACCESS_TOKEN_EXPIRES_IN as i64)),
            refresh_token_expires_at: Set(now + Duration::seconds(REFRESH_TOKEN_EXPIRES_IN as i64)),
            scope: Set(scope),
        };

        new_token_pair.insert(db).await
    }

    pub async fn verify_email(db: &DbConn, user_id: &str) -> Result<users::Model, DbErr> {
        let user = users::Entity::find_by_id(user_id)
            .one(db)
            .await?
            .ok_or(DbErr::RecordNotFound("User not found".to_string()))?;

        let user = users::ActiveModel {
            email_verified: Set(true),
            ..user.into()
        };

        user.update(db).await
    }
}
