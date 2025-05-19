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
#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DbBackend, MockDatabase, MockExecResult};

    fn mock_user_model() -> users::Model {
        users::Model {
            id: 1.to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "hashedpassword".to_string(),
            discriminator: 1234,
            email_verified: false,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn mock_token_pair_model() -> oauth2_token_pairs::Model {
        oauth2_token_pairs::Model {
            id: 1.to_string(),
            user_id: "1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            r#type: "Bearer".to_string(),
            access_token_expires_at: OffsetDateTime::now_utc(),
            refresh_token_expires_at: OffsetDateTime::now_utc(),
            scope: 1,
        }
    }

    #[tokio::test]
    async fn test_get_user_by_username_found() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_query_results(vec![vec![mock_user_model()]])
            .into_connection();

        let user = Query::get_user_by_username(&db, "testuser").await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_get_user_by_username_not_found() {
        let db = MockDatabase::new(DbBackend::Postgres).into_connection();

        let user = Query::get_user_by_username(&db, "notfound").await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_get_user_by_email_found() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_query_results(vec![vec![mock_user_model()]])
            .into_connection();

        let user = Query::get_user_by_email(&db, "test@example.com")
            .await
            .unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn test_get_user_by_email_not_found() {
        let db = MockDatabase::new(DbBackend::Postgres).into_connection();

        let user = Query::get_user_by_email(&db, "notfound@example.com")
            .await
            .unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_create_user() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![mock_user_model()]])
            .into_connection();

        let user = Mutation::create_user(&db, "testuser", "test@example.com", "password")
            .await
            .unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_update_user() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![mock_user_model()]])
            .into_connection();

        let user = mock_user_model();
        let updated = Mutation::update_user(&db, user).await.unwrap();
        assert_eq!(updated.username, "testuser");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        let result = Mutation::delete_user(&db, "1").await.unwrap();
        assert_eq!(result.rows_affected, 1);
    }

    #[tokio::test]
    async fn test_create_oauth2_token_pair() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![mock_token_pair_model()]])
            .into_connection();

        let token_pair =
            Mutation::create_oauth2_token_pair(&db, "1", "access", "refresh", "Bearer", 1)
                .await
                .unwrap();
        assert_eq!(token_pair.user_id, "1");
        assert_eq!(token_pair.access_token, "access");
    }

    #[tokio::test]
    async fn test_verify_email_success() {
        let mut user = mock_user_model();
        user.email_verified = false;

        let db = MockDatabase::new(DbBackend::Postgres)
            .append_query_results(vec![vec![user.clone()]])
            .append_exec_results(vec![MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results(vec![vec![{
                let mut verified_user = user.clone();
                verified_user.email_verified = true;
                verified_user
            }]])
            .into_connection();

        let verified = Mutation::verify_email(&db, "1").await.unwrap();
        assert!(verified.email_verified);
    }

    #[tokio::test]
    async fn test_verify_email_not_found() {
        let db = MockDatabase::new(DbBackend::Postgres).into_connection();

        let result = Mutation::verify_email(&db, "999").await;
        assert!(matches!(result, Err(DbErr::RecordNotFound(_))));
    }
}
