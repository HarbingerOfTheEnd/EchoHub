use std::{env::var, error::Error, path::Path};

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &[Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("protos")
        .join("auth.proto")];
    let includes = &[Path::new(env!("CARGO_MANIFEST_DIR")).join("protos")];
    let out_dir = var("OUT_DIR").unwrap();
    let descriptor_path = Path::new(&out_dir).join("auth_descriptor.bin");

    configure()
        .build_client(false)
        .build_server(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(protos, includes)?;

    Ok(())
}
