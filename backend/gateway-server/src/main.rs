use std::{env::var, net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use async_graphql::{EmptyMutation, EmptySubscription, Schema, http::GraphiQLSource};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    Extension, Router,
    response::{Html, IntoResponse},
    routing::{get, get_service},
};
use axum_server::Server;
use dotenvy::from_filename;
#[macro_use]
extern crate tracing;
use tracing_subscriber::{EnvFilter, fmt};

use crate::{schema::Query, v1::client::GrpcClient};

mod schema;
mod v1;

type GatewaySchema = Schema<Query, EmptyMutation, EmptySubscription>;

#[tokio::main]
async fn main() -> Result<()> {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    from_filename(env_path).context("Failed to load .env file")?;

    fmt()
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let address = var("ADDRESS")
        .context("ADDRESS not set")?
        .parse::<SocketAddr>()
        .context("Failed to parse ADDRESS")?;

    let grpc_client = GrpcClient::new()
        .await
        .context("Failed to create gRPC client")?;
    let schema = Schema::build(Query::default(), EmptyMutation, EmptySubscription)
        .data(grpc_client)
        .finish();

    let router = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .route_service(
            "/subscriptions",
            get_service(GraphQLSubscription::new(schema.clone())),
        )
        .layer(Extension(schema));

    Server::bind(address)
        .serve(router.into_make_service())
        .await
        .context("Failed to start server")
}

async fn graphql_playground() -> impl IntoResponse {
    Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/subscriptions")
            .finish(),
    )
}

async fn graphql_handler(
    Extension(schema): Extension<GatewaySchema>,
    request: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(request.into_inner()).await.into()
}
