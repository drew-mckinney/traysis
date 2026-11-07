//! Compiles `proto/traysis/v1/*.proto` with `protox`, a pure-Rust protobuf
//! compiler, so building needs no system `protoc`.

use std::path::PathBuf;

const PROTO_FILES: &[&str] = &["traysis/v1/inventory.proto", "traysis/v1/envelope.proto"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    println!("cargo:rerun-if-changed={}", root.display());
    let descriptors = protox::compile(PROTO_FILES, [&root])?;
    prost_build::compile_fds(descriptors)?;
    Ok(())
}
