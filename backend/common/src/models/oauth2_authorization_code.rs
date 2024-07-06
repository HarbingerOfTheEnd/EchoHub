use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel, Eq, PartialEq)]
#[sea_orm(table_name = "oauth2_authorization_code")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub code: String,
    pub user_id: String,
    pub client_id: String,
}

#[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
