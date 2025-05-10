pub use sea_orm_migration::prelude::*;

mod m20250407_172424_create_table;
mod m20250510_150907_create_table_oauth2_token_pair;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250407_172424_create_table::Migration),
            Box::new(m20250510_150907_create_table_oauth2_token_pair::Migration),
        ]
    }
}
