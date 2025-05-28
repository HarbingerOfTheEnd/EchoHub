use std::error::Error;

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &["../auth-server/protos/v1/auth.proto"];
    let includes = &["../auth-server/protos", "../auth-server/protos/google"];

    configure()
        .build_client(true)
        .build_server(false)
        .type_attribute("SignupRequest", "#[derive(async_graphql::InputObject)]")
        .type_attribute("SignupResponse", "#[derive(async_graphql::SimpleObject)]")
        .type_attribute("SigninRequest", "#[derive(async_graphql::InputObject)]")
        .type_attribute("SigninResponse", "#[derive(async_graphql::SimpleObject)]")
        .type_attribute("TokenResponse", "#[derive(async_graphql::SimpleObject)]")
        .type_attribute(
            "VerifyEmailRequest",
            "#[derive(async_graphql::InputObject)]",
        )
        .compile_protos(protos, includes)?;

    Ok(())
}
