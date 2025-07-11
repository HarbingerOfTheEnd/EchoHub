use std::io::Error;

use tonic_build::configure;

fn main() -> Result<(), Error> {
    let protos = &["proto/auth.proto"];
    let includes = &["proto"];
    let file_descriptor_path = "auth_descriptor.bin";

    configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(file_descriptor_path)
        .compile_protos(protos, includes)
}
