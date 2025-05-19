use std::{env::var, error::Error, path::Path};

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &["../auth-server/protos/v1/auth.proto"];
    let includes = &["../auth-server/protos", "../auth-server/protos/google"];
    let out_dir = var("OUT_DIR").unwrap();
    let descriptor_path = Path::new(&out_dir).join("gateway_descriptor.bin");

    configure()
        .build_client(true)
        .build_server(false)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(protos, includes)?;

    Ok(())
}
