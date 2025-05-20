use async_graphql::MergedObject;
use auth_schema::AuthMutation;

pub(crate) mod auth_schema;

#[derive(Default, MergedObject)]
pub(crate) struct Query(AuthMutation);
