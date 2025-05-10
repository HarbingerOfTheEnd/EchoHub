use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Oauth2TokenPairs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::Id)
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::Type)
                            .string_len(12)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::AccessToken)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::RefreshToken)
                            .text()
                            .unique_key()
                            .not_null()
                            .default(Value::String(None)),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::AccessTokenExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::RefreshTokenExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Oauth2TokenPairs::UserId)
                            .string_len(24)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Oauth2TokenPairs::Scope).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_oauth2_token_pairs_user_id")
                            .from(Oauth2TokenPairs::Table, Oauth2TokenPairs::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Oauth2TokenPairs::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Oauth2TokenPairs {
    Table,
    Id,
    Type,
    AccessToken,
    RefreshToken,
    AccessTokenExpiresAt,
    RefreshTokenExpiresAt,
    UserId,
    Scope,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
