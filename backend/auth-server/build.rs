use std::{env, error::Error, path::Path};

use tonic_build::configure;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = &[Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("protos")
        .join("auth.proto")];
    let includes = &[Path::new(env!("CARGO_MANIFEST_DIR")).join("protos")];

    configure().compile_protos(protos, includes)?;

    Ok(())
}
