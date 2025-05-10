use std::{env::var, error::Error, path::Path};

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &["protos/v1/auth.proto"];
    let includes = &["protos", "protos/google"];
    let out_dir = var("OUT_DIR").unwrap();
    let descriptor_path = Path::new(&out_dir).join("auth_descriptor.bin");

    configure()
        .build_client(false)
        .build_server(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(protos, includes)?;

    Ok(())
}
