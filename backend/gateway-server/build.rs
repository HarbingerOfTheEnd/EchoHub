use std::error::Error;

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &["../auth-server/protos/v1/auth.proto"];
    let includes = &["../auth-server/protos", "../auth-server/protos/google"];

    configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(protos, includes)?;

    Ok(())
}
