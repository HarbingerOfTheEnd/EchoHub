use std::time::Duration;

use async_graphql::{Context, Object, Subscription};
use tokio_stream::{Stream, StreamExt, iter};

pub(crate) struct Query;
pub(crate) struct Subscription;

#[Object]
impl Query {
    async fn hello(&self, _ctx: &Context<'_>) -> &str {
        info!("Hello from Query");
        "Hello, world!"
    }
}

#[Subscription]
impl Subscription {
    async fn str(&self) -> impl Stream<Item = i32> {
        info!("Hello from Subscription");
        iter(1..=100).throttle(Duration::from_secs(1))
    }
}
